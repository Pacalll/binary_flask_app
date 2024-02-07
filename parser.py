import re

def parse_strace_output(data):
    # split the data after every \n
    syscall_list = data.split("\n")
    # regex for syscalls
    #    mmap(NULL, 85179, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f5e2eabc000
    # mmap = syscallname
    # everything inside () are arguments for the specific syscall
    # 0x7f5e2eabc000 is return value for syscall
    syscall_pattern = re.compile(r'(\w+)\((.*)\)\s*=\s*(.*)')
    syscall_list_sanitized = []

    for item in syscall_list:
        match = syscall_pattern.match(item)
        if match:
            syscall_name, syscall_args, syscall_result = match.groups()
            syscall_dict = {
                'syscall_name': syscall_name,
                'syscall_args': syscall_args,
                'syscall_result': syscall_result
            }
            syscall_list_sanitized.append(syscall_dict)
    return syscall_list_sanitized