import os
import glob
import shutil
import re
import subprocess
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
from utils.logger_config import LoggerConfig  # Import LoggerConfig
from config import config
import json

from utils.utils import ensure_directory_exists


class ELFParser:
    """Class to analyze ELF files and their required dynamic libraries."""

    def __init__(self, binary_path, search_dir):
        self.binary_path = binary_path
        self.search_dir = search_dir
        self.libraries = []
        self.all_libraries_data = {} # Dictionary to store library name path and other infos
        self.dangerous_functions_libs = []
        self.common_functions = {}
        self.found_libraries = {}  
        self.copied_files = {}  # To store copied libraries and program paths
        self.config = config.LivaConfig
        self.config.set_binary_path(self.binary_path, None)
        config.LivaConfig.init_db()
        # Get the logger configured by LoggerConfig
        # The module name for logging will be 'ELFAnalyzer'
        self.logger = LoggerConfig.configure_logger('ELFAnalyzer')
        

    def get_needed_libraries(self):
        """Extract dynamic libraries required by the ELF file (readelf -d equivalent via pyelftools)."""
        needed = []
        try:
            with open(self.binary_path, 'rb') as f:
                elf = ELFFile(f)
                for section in elf.iter_sections():
                    if isinstance(section, DynamicSection):
                        for tag in section.iter_tags():
                            if tag.entry.d_tag == 'DT_NEEDED':
                                needed.append(tag.needed)
        except FileNotFoundError:
            self.logger.error(f"File not found: {self.binary_path}")
            raise ValueError(f"File not found: {self.binary_path}")
        except Exception as e:
            self.logger.error(f"Failed to parse ELF file: {str(e)}")
            raise RuntimeError(f"Failed to parse ELF file: {str(e)}")

        self.libraries = needed
        self.logger.info(f"Found {len(needed)} dynamic libraries.")
        return needed

    def find_libraries(self):
        """Find the paths of required libraries."""
        found_libraries = {}
        for lib in self.libraries:
            # Search for the library in the specified directory
            lib_path = glob.glob(os.path.join(self.search_dir, f"**/{lib}"), recursive=True)
            if lib_path:
                found_libraries[lib] = {"path": lib_path[0]}  # Store the first match
            else:
                found_libraries[lib] = {"path": None}   # No match found
        self.found_libraries = found_libraries
        self.logger.info(f"Found paths for {len(found_libraries)} libraries.")
        return found_libraries



    def move_file_to_result(self, file_path, target_dir):
        """Move a file to the result directory, keeping the original filename."""
        base_name = os.path.basename(file_path)
        target_path = os.path.join(target_dir, base_name)

        # Skip if the file already exists in the target directory
        if os.path.exists(target_path):
            self.logger.info(f"File {base_name} already exists, skipping.")
        else:
            shutil.copy(file_path, target_path)  # Copy file instead of moving
            self.logger.info(f"File {file_path} copied to {target_path}")

        # Store the copied file path in the copied_files dictionary
        return target_path

    def save_results(self):
        """Save the results by copying ELF file and libraries to the result folder."""
        # Create the result directory using the 'filename_MD5prefix' format
        result_dir = self.config.directory_map["binary"]
        # Copy the main file to the result folder, keeping the original name
        copied_path = self.move_file_to_result(self.binary_path, result_dir)

        # Update the found_libraries with the new copied paths
        self.found_libraries[os.path.basename(self.binary_path)] = {"path": copied_path}

        # Copy the found libraries to the result folder, keeping their original names
        for lib, data in self.found_libraries.items():
            lib_path = data.get("path")
            if lib_path and lib_path != copied_path:  # Avoid copying the main program again
                copied_path = self.move_file_to_result(lib_path, result_dir)
                self.found_libraries[lib] = {"path": copied_path}  # Update with copied path

        self.logger.info(f"Results saved to: {result_dir}")

    def generate_symbols_json(self):
        """Generate the symbol tables for all libraries and save them as JSON, 
        along with U_symbol and T_symbol for each library using nm -D."""
        # all_libraries_data = {}

        for lib, lib_data in self.found_libraries.items():
            lib_path = lib_data.get("path")
            if lib_path:
                self.logger.info(f"Processing library: {lib}")

                # Get the symbols using 'nm -D' and parse them into U_symbol and T_symbol
                U_symbols = []
                T_symbols = {}

                try:
                    # Parse dynamic symbols (nm -D equivalent) via pyelftools
                    with open(lib_path, 'rb') as f:
                        elf = ELFFile(f)
                        dynsym = elf.get_section_by_name('.dynsym')
                        if dynsym is not None:
                            for sym in dynsym.iter_symbols():
                                name = sym.name
                                if not name:
                                    continue
                                shndx = sym.entry.st_shndx
                                if shndx == 'SHN_UNDEF':
                                    U_symbols.append(name)
                                elif sym.entry.st_info['type'] == 'STT_FUNC' or sym.entry.st_info['type'] == 'STT_NOTYPE':
                                    T_symbols[name] = '%08x' % sym.entry.st_value
                except Exception as e:
                    self.logger.warning(f"Failed to parse symbols for {lib}: {e}")

                # Update the found_libraries dictionary with U_symbol and T_symbol
                
       

                main_binary_name = os.path.basename(self.binary_path)
                current_lib_name = os.path.basename(lib)  
                if current_lib_name == main_binary_name:
                    lib_type = "main"
                elif "libc.so" in current_lib_name.lower():  
                    lib_type = "libc"
                else:
                    lib_type = "libs"

                self.all_libraries_data[lib] = {
                    "type": lib_type,
                    "path": lib_path,
                    "U_symbol": U_symbols,
                    "T_symbol": T_symbols
                }
            else:
                self.logger.warning(f"Library {lib} not found.")

        # Save the updated found_libraries to a JSON file
        result_file = os.path.join(config.LivaConfig.config["ResultDir"]["root"], config.LivaConfig.project_path, self.config.project_name, 'found_libraries.json')
        try:
            with open(result_file, 'w') as f:
                json.dump(self.all_libraries_data, f, indent=4)
            self.logger.info(f"Found libraries and symbols saved to {result_file}")
        except Exception as e:
            self.logger.error(f"Failed to save found libraries to JSON: {e}")



    def check_dangerous_functions_in_libraries(self):
        dangerous_functions_libs = []
        vul_set = []
        vul_config = self.config.export_vulconfig_function()
        for key, value in vul_config.items():
            vul_set.extend(value)
        
        for key,  value in self.all_libraries_data.items():
            intersection = []
            if value["type"] == "libs" :
                intersection = list(set(value["U_symbol"]) & set(vul_set))
            

            if len(intersection) != 0 :
                dangerous_functions_libs.append(key)
        
        self.dangerous_functions_libs = dangerous_functions_libs

        pass


                
    def search_common_functions(self):
        """
        Identify common functions between the main binary and dangerous libraries,
        and save them as a dict of {function_name: address}.
        """
        import os
        main_binary_name = os.path.basename(self.binary_path)

        for lib_name in self.dangerous_functions_libs:
            lib_symbols = self.all_libraries_data[lib_name]["T_symbol"]
            main_undefined = self.all_libraries_data[main_binary_name]["U_symbol"]

            # Find common function names
            common_names = set(lib_symbols.keys()) & set(main_undefined)

            if common_names :
                # Keep {function_name: address} from the library
                self.common_functions[lib_name] = {
                    name: lib_symbols[name] for name in common_names
                }
        self.common_functions[main_binary_name] = self.all_libraries_data[main_binary_name]["T_symbol"]
        # Save results to JSON
        result_file = os.path.join(self.config.directory_map["elfParse"], 'common_functions.json')

        try:
            with open(result_file, 'w') as f:
                json.dump(self.common_functions, f, indent=4)
            self.logger.info(f"Found common functions saved to {result_file}")
        except Exception as e:
            self.logger.error(f"Failed to save found common functions to JSON: {e}")