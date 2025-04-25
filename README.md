# Summary
The verifyhash applet included in this custom BusyBox OS build checks for any tampering of BusyBox's binary by using hashing its own binary at /proc/self/exe and comparing that hash to a known "good" hash.
SHA-512 is used as the hashing algorithm.

# Design
This functionality is designed as an applet that can be configured as a "Miscellaneous Utility" to be included in your BusyBox build.
The applet stores the known "good" hash in a custom ELF section called .hashsig. A separate patching script is used after initial build of BusyBox to "patch" the known good hash computed from the build into the ELF section. This section is excluded from the hash computation to avoid circular dependency issues.
When hashing, the binary maps itself via mmap() from /proc/self/exe, iterates through each ELF header, and hashes each section of that header (ignoring .hashsig).
The hashes are then compared and the applet will output a message either verifying a match or mismatch.

# Instructions
1. Download this BusyBox source code locally.
2. Access the root directory of the BusyBox code with this command: `cd busybox-1.36.1`
4. Configure a default build that includes a majority of applets using the following command in the root directory: `make defconfig`
5. Add the verifyhash applet to the build by using the menu: `make menuconfig`
6. While on the menu configuration portal, scroll down to "Miscellaneous Utils" and go all the way down to check mark "verifyhash"
7. Save the configuration, and finally build BusyBox: `make`
8. Check that BusyBox successfully built by using the following command: `./busybox` This will list all the applets included in this build. Check that verifyhash is in this list.
9. Now go back one directory. Run the patching script: `chmod +x ./patch_hash.sh
10. Upon successful patching re-enter the BusyBox root directory and run the applet: `./busybox verifyhash`
11. Finally, test for tampering by editing the binary slightly and re-running verifyhash. I personally installed hexedit to do this. Make sure to edit portions of the binary that aren't executables to avoid segmentation faults.
