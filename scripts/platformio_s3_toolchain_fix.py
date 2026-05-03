from pathlib import Path

Import("env")


def append_if_exists(path):
    if path.exists():
        env.Append(CPPPATH=[str(path)])


toolchain_dir = env.PioPlatform().get_package_dir("toolchain-xtensa-esp32s3")
if toolchain_dir:
    cxx_root = (
        Path(toolchain_dir)
        / "xtensa-esp32s3-elf"
        / "include"
        / "c++"
        / "8.4.0"
    )
    append_if_exists(cxx_root)
    append_if_exists(cxx_root / "xtensa-esp32s3-elf")
    append_if_exists(cxx_root / "xtensa-esp32s3-elf" / "no-rtti")
    append_if_exists(cxx_root / "backward")
