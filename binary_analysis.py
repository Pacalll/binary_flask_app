import json
import sqlite3
import subprocess
from datetime import datetime
import parser


def run_binary_analysis_rabin2(file, binary_id):
    command = f"chmod +x uploads/{file.filename};rabin2 -Ij uploads/{file.filename}"
    try:
        data = subprocess.check_output(command , shell=True, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: Cant execute rabin2 command or with errors !")
        return False
    try:
        connection = sqlite3.connect("binary_meta.db")
        cursor = connection.cursor()
    except Exception as e:
        print(f"Error: cannot connect to database!")
        return False
    cursor.execute("""
            CREATE TABLE IF NOT EXISTS binary_info_rabin2(
                binary_id number,
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
    #TODO check if uploaded file is binary ?!?
    cursor.execute("""
                INSERT INTO binary_info_rabin2(
                     binary_id,
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
        binary_id,
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
def run_binary_analysis_strace(file,binary_id):
    command = f"chmod +x uploads/{file.filename};strace uploads/{file.filename}"
    try:
        data = subprocess.check_output(command, shell=True, universal_newlines=True,stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print(f"Error: Cant execute strace command or with errors ! {e}")
        return False
    data_parsed = parser.parse_strace_output(data)
    # connect to db and create cursor obj.
    try:
        conn = sqlite3.connect('binary_meta.db')
        cursor = conn.cursor()
        # create sql table if not exists
        cursor.execute("""
                CREATE TABLE IF NOT EXISTS binary_info_strace(
                    binary_id number,
                    syscall text,
                    arguments text, 
                    result text          
                )
            """)
    except Exception as e:
        print(f"Error: Cant create table for strace!!")
    for syscall in data_parsed:
        cursor.execute("""
                            INSERT INTO binary_info_strace (
                                binary_id,
                                syscall,
                                arguments,
                                result
                        )VALUES (?,?,?,?)""", (
            binary_id,
            syscall["syscall_name"],
            syscall["syscall_args"],
            syscall["syscall_result"]
        ))
    conn.commit()
    conn.close()
def run_binary_analysis_strings(file, binary_id):
    command = f"chmod +x uploads/{file.filename};strings uploads/{file.filename}"
    try:
        data = subprocess.check_output(command, shell=True, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: Cant execute string command or with errors !")
    try:
            conn = sqlite3.connect('binary_meta.db')
            cursor = conn.cursor()
    except Exception as e:
            print(f"Error: Cant connect to db!!")
    try:
        cursor.execute("""
           CREATE TABLE IF NOT EXISTS binary_info_strings(
               binary_id number, 
               paddr text,
               vaddr text,
               length number,
               size number,
               section text,
               type text,
               string text
        );
        """)
    except Exception as e:
        print(f"Error: Cant create table for strings!!")
    try:
        #Connect to db and create cursor obj.
        conn = sqlite3.connect("binary_meta.db")
        cursor = conn.cursor()
        #for every line (ascii string) split at the end and insert into db table
        for line in data.split("\n"):
                    cursor.execute('''
                    INSERT INTO binary_info_strings(
                        binary_id,
                        string)
                    VALUES (?,?) 
                    ''',(
                        binary_id,
                        line,))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error: Cant insert data into string table! {e}")
def run_binary_analysis_library(file,binary_id):
    command = f"chmod +x uploads/{file.filename};rabin2 -lj uploads/{file.filename}"
    try:
        data = subprocess.check_output(command, shell=True, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: Cant execute rabin2 command for libraries or with errors !")
    try:
        conn = sqlite3.connect('binary_meta.db')
        cursor = conn.cursor()
    except Exception as e:
        print(f"Error: Cant connect to db!!")
    try:
        cursor.execute("""
               CREATE TABLE IF NOT EXISTS library(   
                   binary_id number, 
                   library_name text
            );
            """)
    except Exception as e:
        print(f"Error: Cant create table for library!!")
    try:
        # for every line (ascii string) split at the end and insert into db table
        data = json.loads(data)
        libary_names = data.get("libs",[])
        for line in libary_names:
            cursor.execute('''
                        INSERT INTO library(
                            binary_id,
                            library_name
                        )
                        VALUES (?,?) 
                        ''', (
                    binary_id,
                    line,))
        conn.commit()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
def run_binary_create_binary_table(file):
    name = file.filename
    time_of_analysis = datetime.now()
    try:
        conn = sqlite3.connect('binary_meta.db')
        cursor = conn.cursor()
    except Exception as e:
        print(f"Error: Cant connect to db!!")
        return
    try:
        cursor.execute("""
               CREATE TABLE IF NOT EXISTS binary(   
                   binary_id Integer PRIMARY KEY, 
                   binary_name text, 
                   time_of_analysis date
            );
            """)
        cursor.execute("""
                   INSERT INTO binary (
                                binary_name,
                                time_of_analysis
                        )VALUES (?,?)""",
                       (name, time_of_analysis))
        conn.commit()
        binary_id = cursor.lastrowid
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
    return binary_id


def get_binary_analysis(table_name):
    try:
        connection = sqlite3.connect("binary_meta.db")
        cursor = connection.cursor()
        query = f"SELECT * FROM {table_name};"
        cursor.execute(query)
        data = (cursor.fetchall())
        cursor.close()
        return data
    except Exception as e:
        print(f"Error: cannot connect to database!")
        return False
    finally:
        connection.close()

def calc_syscalls(binary):
    return

def run_binary_analysis(binary):
    binary_id = run_binary_create_binary_table(binary)
    run_binary_analysis_rabin2(binary, binary_id)
    run_binary_analysis_strace(binary, binary_id)
    run_binary_analysis_strings(binary, binary_id)
    run_binary_analysis_library(binary, binary_id)
