import json
import os
import sqlite3
from datetime import datetime
import matplotlib.pyplot as plt
import parser
import docker


def run_binary_analysis_rabin2(container, file, binary_id):
    rabin2_command = f"rabin2 -Ij /app/uploads/{file.filename}"

    try:
        # rabin2-Befehl im Docker-Container ausführen
        rabin2_result = container.exec_run(rabin2_command)
        rabin2_output = rabin2_result.output.decode("utf-8")
    except Exception as e:
        print(f"Error: Unable to execute rabin2 command in Docker container! {e}")
        return False
    try:
        # SQLite-Verbindung herstellen
        conn = sqlite3.connect('binary_meta.db')
        cursor = conn.cursor()

        # Tabelle erstellen, falls sie nicht existiert
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
        # Daten aus der Ausgabe parsen und in die SQLite-Datenbank einfügen
        meta_data_python_dict = json.loads(rabin2_output)['info']
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
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
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
        conn.commit()
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        cursor.close()
        conn.close()
    return True
def run_binary_analysis_strace(container, file,binary_id):
    command = f"strace uploads/{file.filename}"
    try:
        # Strace-Befehl im Docker-Container ausführen
        container.exec_run(f"chmod +x uploads/{file.filename}")
        strace_result = container.exec_run(command)
    except Exception as e:
        print(f"Error: Unable to execute strace command in Docker container! {e}")
        return False
    data_parsed = parser.parse_strace_output(strace_result.output.decode("utf-8"))
    # connect to db and create cursor obj.
    try:
        conn = sqlite3.connect('binary_meta.db')
        cursor = conn.cursor()
        # create sql table if not exists
        cursor.execute("""
                CREATE TABLE IF NOT EXISTS binary_info_strace(
                    binary_id number,
                    categorie_id number,
                    syscall text,
                    arguments text, 
                    result text          
                )
            """)
    except Exception as e:
        print(f"Error: Cant create table for strace!!")
    for syscall in data_parsed:
        categorie_id = get_syscall_category_for_syscall(syscall["syscall_name"])
        cursor.execute("""
                            INSERT INTO binary_info_strace (
                                binary_id,
                                categorie_id,
                                syscall,
                                arguments,
                                result
                        )VALUES (?,?,?,?,?)""", (
            binary_id,
            categorie_id,
            syscall["syscall_name"],
            syscall["syscall_args"],
            syscall["syscall_result"]
        ))
    conn.commit()
    conn.close()
def run_binary_analysis_strings(container, file, binary_id):
    command = f"strings /app/uploads/{file.filename}"
    try:
        result = container.exec_run(command)
    except Exception as e:
        print(f"Cant start execute command in docker container ! Error: {e}")
        return False
    try:
        # SQLite-Verbindung herstellen
        conn = sqlite3.connect('binary_meta.db')
        cursor = conn.cursor()

        # Tabelle für Strings erstellen, falls sie nicht existiert
        cursor.execute("""
                CREATE TABLE IF NOT EXISTS binary_info_strings(
                    binary_id number, 
                    string text
                );
            """)

        # Daten aus der Ausgabe parsen und in die SQLite-Datenbank einfügen
        for line in result.output.decode("utf-8").split("\n"):
            cursor.execute('''
                    INSERT INTO binary_info_strings(
                        binary_id,
                        string
                    )
                    VALUES (?, ?)
                ''', (binary_id, line))
        conn.commit()

    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

    return True
def run_binary_analysis_library(container, file, binary_id):
    command = f"rabin2 -lj /app/uploads/{file.filename}"
    try:
        result = container.exec_run(command)
    except Exception as e:
        print(f"Cant start execute command in docker container ! Error: {e}")
        return False
    try:
        # SQLite-Verbindung herstellen
        conn = sqlite3.connect('binary_meta.db')
        cursor = conn.cursor()
        try:
            # Tabelle erstellen, falls sie nicht existiert
            cursor.execute("""
                        CREATE TABLE IF NOT EXISTS library(
                            binary_id number,
                            library_name text
                        );
            """)
            try:
                # Daten aus der Ausgabe parsen und in die SQLite-Datenbank einfügen

                data_lib = json.loads(result.output.decode("utf-8"))
                library_names = data_lib.get("libs", [])
                for line in library_names:
                    cursor.execute('''
                        INSERT INTO library(
                                binary_id,
                                library_name
                        )
                        VALUES (?, ?)
                    ''', (binary_id, line))
                conn.commit()
            except Exception as e:
                print(f"Cant insert data into library table ! {e}")
                return False;
        except Exception as e:
            print(f"Cant create table for library! {e}:")
            return False
    except Exception as e:
        print(f"Cant connec to db ! {e}")
        return False
    finally:
        cursor.close()
        conn.close()
    return True
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
        return data
    except Exception as e:
        print(f"Error: cannot connect to database! {e}")
        return False
    finally:
        cursor.close()
        connection.close()

def create_table_syscall_categories():
    try:
        conn = sqlite3.connect('binary_meta.db')
        cursor = conn.cursor()
        # Create table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS syscall_categories (
                categorie_id INTEGER PRIMARY KEY,
                categorie TEXT       
            )
        """)
        cursor.execute("SELECT COUNT(*) FROM syscall_categories;")
        count = cursor.fetchone()[0]
        if count == 0:
            # Insert data into the table
            cursor.execute("""
                INSERT INTO syscall_categories (categorie) VALUES (?),(?),(?),(?),(?),(?),(?)
            """, ('Netzwerk', 'Prozessmanagement', "Dateimanagement", "Gerätemanagement", "Systeminformationen", 'Speichermanagement' ,"Sonstige"))
        conn.commit()
    except Exception as e:
            print(f"Error: Can't create table for syscall categories! {e}")
    finally:
            cursor.close()
            conn.close()
def get_syscall_category_for_syscall(syscall):
    try:
        conn = sqlite3.connect("binary_meta.db")
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT category_id FROM syscall_to_categories WHERE syscall_name = ?", (syscall,))
            result = cursor.fetchone()
            return result[0] if result else 7
        except Exception as e:
            print(f"Error: Can't get category_id for syscall ! {e}")
            return False
    except Exception as e:
        print(f"Error: Can't connect to db ! {e}")
        return False
    finally:
        cursor.close()
        conn.close()
def calculate_syscall_overview(binary_id):
    try:
        connection = sqlite3.connect("binary_meta.db")
        cursor = connection.cursor()
        cursor.execute("SELECT categorie FROM syscall_categories;")
        categories = [row[0] for row in cursor.fetchall()]

        syscall_counts = []
        filtered_categories = []

        for category_id in range(1, len(categories) + 1):
            query = f"SELECT COUNT(*) FROM binary_info_strace WHERE binary_id = {str(binary_id)} AND categorie_id = {category_id};"
            count = cursor.execute(query).fetchone()[0]

            if count > 0:
                syscall_counts.append(count)
                filtered_categories.append(categories[category_id - 1])
        calculate_syscall_overview_image(syscall_counts, filtered_categories, binary_id)
    except Exception as e:
        print(f"Error: cannot connect to database! {e}")
        return False
    finally:
        cursor.close()
        connection.close()


def calculate_syscall_overview_image(syscall_count, syscall_categories, binary_id):
    fig, ax = plt.subplots()
    ax.pie(syscall_count, labels=syscall_categories)
    ax.set_title(f"Syscall Overview for Binary {binary_id}", fontsize=20, fontweight="bold")
    path_of_syscall_image = f"static/syscall_overview_image{binary_id}.png"
    plt.savefig(path_of_syscall_image, format="PNG")
    plt.close()

def create_table_syscall_to_category():
    try:
        conn = sqlite3.connect('binary_meta.db')
        cursor = conn.cursor()
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS syscall_to_categories (
                    syscall_name TEXT PRIMRY KEY,
                    category_id INTEGER       
                )
            """)
        except Exception as e:
            print(f"Error: cannot create table for syscall_to_categories! {e}")
            return False
    except Exception as e:
        print(f"Error: cannot connect to database! {e}")
        return False
    finally:
        cursor.close()
        conn.close()
    return True
def insert_syscall_category(syscall, category_id):
    try:
        conn = sqlite3.connect('binary_meta.db')
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT COUNT(*) FROM syscall_to_categories WHERE syscall_name = ?", (syscall,))
            count = cursor.fetchone()[0]
            if count ==0:
                cursor.execute("INSERT INTO syscall_to_categories ("
                           "syscall_name,"
                           " category_id) VALUES (?, ?)",
                           (syscall, category_id))
                conn.commit()
        except Exception as e:
            print(f"Cant insert syscall into table ! {e}")
    except Exception as e:
        print(f"Cant connect to database! {e}")
    finally:
        cursor.close()
        conn.close()

def start_docker_container():
    source_path = os.path.abspath(f"uploads/")
    image_name = f"binary_analysis_image"
    target_path = f"/app/uploads"
    volumes = {source_path: {'bind': target_path, 'mode': 'rw'}}
    client = docker.from_env()

    try:
        return client.containers.run(image_name, tty=True, detach=True, volumes=volumes, working_dir="/app")
    except Exception as e:
        print(f"Error: Unable to start Docker container! {e}")
        return None
def stop_and_remove_container(container):
    if container:
        container.stop()
        container.remove()

def run_binary_analysis(binary):
    container = start_docker_container()
    binary_id = run_binary_create_binary_table(binary)
    create_table_syscall_to_category()
    insert_syscall_category("accept", 1)
    insert_syscall_category("close", 3)
    insert_syscall_category("connect", 1)
    insert_syscall_category("socket",1)
    insert_syscall_category("open",3)
    insert_syscall_category("arch_prctl",5)
    insert_syscall_category("brk",5)
    insert_syscall_category("execve", 2)
    insert_syscall_category("access", 3)
    insert_syscall_category("read", 3)
    insert_syscall_category("newfstatat",3)
    insert_syscall_category("pread64", 3)
    insert_syscall_category("mmap", 6)
    insert_syscall_category("mprotect",6)
    run_binary_analysis_rabin2(container, binary, binary_id)
    run_binary_analysis_strace(container, binary, binary_id)
    run_binary_analysis_strings(container, binary, binary_id)
    run_binary_analysis_library(container, binary, binary_id)

    create_table_syscall_categories()
    calculate_syscall_overview(binary_id)
    stop_and_remove_container(container)



