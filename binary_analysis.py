import json
import sqlite3
import subprocess
def run_binary_analysis_rabin2(file):
    command = f"cd uploads/;chmod +x {file.filename}; rabin2 -Ij {file.filename}"
    try:
        data = subprocess.check_output(command , shell=True, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: Cant execute command or with errors !")
        return False
    try:
        connection = sqlite3.connect("binary_analysis.db")
        cursor = connection.cursor()
    except Exception as e:
        print(f"Error: cannot connect to database!")
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS binary_info_rabin2(
                path_of_binary text,
                architecture text,
                baseaddr text,
                size_of_binary text,
                format_of_binary text,
                mod_of_binary text,
                is_canary number,
                is_stack_memory_protection number, 
                class_of_binary text,
                compiled text, 
                compiler text,
                is_encrypted_binary number, 
                dbg_file text,
                endian text, 
                havecode number,
                guid text, 
                interpreter_of_binary text, 
                loadaddr text, 
                lang text, 
                linenum number, 
                lsyms number, 
                machine text,
                is_nx text,
                os text, 
                cc text, 
                is_pic text, 
                relocs number, 
                relro text, 
                rpath text, 
                is_sanitize number, 
                is_static_linked number, 
                is_stripped number, 
                subsys text, 
                is_va text,
                checksums text
            );
        """)
    meta_data_python_dict = json.loads(data)['info']
    cursor.execute("""
                INSERT INTO binary_info_rabin2 (
                     path_of_binary,
                     architecture,
                     baseaddr,
                     size_of_binary,
                     format_of_binary,
                     mod_of_binary,
                     is_canary,
                     is_stack_memory_protection, 
                     class_of_binary,
                     compiled, 
                     compiler,
                     is_encrypted_binary, 
                     dbg_file,
                     endian, 
                     havecode,
                     guid, 
                     interpreter_of_binary, 
                     loadaddr, 
                     lang, 
                     linenum, 
                     lsyms, 
                     machine,
                     is_nx,
                     os, 
                     cc, 
                     is_pic, 
                     relocs, 
                     relro, 
                     rpath, 
                     is_sanitize, 
                     is_static_linked, 
                     is_stripped, 
                     subsys, 
                     is_va,
                     checksums

                )VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
        "hello world",
        meta_data_python_dict["arch"],
        meta_data_python_dict["baddr"],
        meta_data_python_dict["binsz"],
        meta_data_python_dict["bintype"],
        meta_data_python_dict["bits"],
        meta_data_python_dict["canary"],
        meta_data_python_dict["injprot"],
        meta_data_python_dict["class"],
        meta_data_python_dict["compiled"],
        meta_data_python_dict["compiler"],
        meta_data_python_dict["crypto"],
        meta_data_python_dict["dbg_file"],
        meta_data_python_dict["endian"],
        meta_data_python_dict["havecode"],
        meta_data_python_dict["guid"],
        meta_data_python_dict["intrp"],
        meta_data_python_dict["laddr"],
        meta_data_python_dict["lang"],
        meta_data_python_dict["linenum"],
        meta_data_python_dict["lsyms"],
        meta_data_python_dict["machine"],
        meta_data_python_dict["nx"],
        meta_data_python_dict["os"],
        meta_data_python_dict["cc"],
        meta_data_python_dict["pic"],
        meta_data_python_dict["relocs"],
        meta_data_python_dict["relro"],
        meta_data_python_dict["rpath"],
        meta_data_python_dict["sanitize"],
        meta_data_python_dict["static"],
        meta_data_python_dict["stripped"],
        meta_data_python_dict["subsys"],
        meta_data_python_dict["va"],
        json.dumps(meta_data_python_dict["checksums"])

    ))
    connection.commit()
    connection.close()

