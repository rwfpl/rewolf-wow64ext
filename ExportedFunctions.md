# Introduction #

Description of exported functions.


# Details #

---

## X64Call ##
DWORD64 X64Call(DWORD64 func, int argC, ...);

Low level function that can call any x64 API from NTDLL.

_func_ - address of **x64** function, can be obtained by **GetProcAddress64()**<br>
<i>argC</i> - number of arguments that will be passed to the <i>func</i><br>
...  - rest of arguments for func<i>, all values should be casted to <b>DWORD64</b></i>

<hr />
<h2>GetModuleHandle64</h2>
DWORD64 GetModuleHandle64(wchar_t<code>*</code> lpModuleName);<br>
<br>
Behaviour similar to x86 version of <b>GetModuleHandle()</b>, but it looks for the module name in the list of loaded x64 libraries. Usually x86  processes under <b>WOW64</b> layer have four x64 libraries: ntdll.dll,   wow64.dll, wow64cpu.dll and wow64win.dll<br>
<br>
<i>lpModuleName</i> - unicode string that represents module name<br>
<br>
<hr />
<h2>GetProcAddress64</h2>
DWORD64 GetProcAddress64(DWORD64 hModule, char<code>*</code> funcName);<br>
<br>
Behaviour similar to x86 version of <b>GetProcAddress()</b>, internally it  uses x64 version of <b>LdrGetProcedureAddress()</b> from NTDLL.<br>
<br>
<i>hModule</i>  - base of x64 module<br>
<i>funcName</i> - function name<br>
<br>
<hr />
<h2>VirtualQueryEx64</h2>
SIZE_T VirtualQueryEx64(HANDLE hProcess, DWORD64 lpAddress, MEMORY_BASIC_INFORMATION64<code>*</code> lpBuffer, SIZE_T dwLength);<br>
<br>
Behaviour similar to x86 version of <b>VirtualQueryEx()</b>, internally it uses x64 version of <b>NtQueryVirtualMemory()</b> from NTDLL.<br>
<br>
<i>hProcess</i> - handle of the process, can be obtained by standard x86 version of <b>OpenProcess()</b> function<br>
<i>lpAddress</i> - base address of the region of pages to be queried<br>
<i>lpBuffer</i> - a pointer to a <b>MEMORY_BASIC_INFORMATION64</b>  structure, it is defined in the standard SDK headers<br>
<i>dwLength</i> - size of the buffer pointed to by the <i>lpBuffer</i> parameter<br>
<br>
<hr />
<h2>ReadProcessMemory64</h2>
BOOL ReadProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T <code>*</code>lpNumberOfBytesRead);<br>
<br>
Behaviour similar to x86 version of <b>ReadProcessMemory()</b>, internally it uses x64 version of <b>NtReadVirtualMemory()( from NTDLL.</b>

<i>hProcess</i> - handle of the process, can be obtained by standard x86 version of <b>OpenProcess()</b> function<br>
<i>lpBaseAddress</i> - base address of the region that will be read<br>
<i>lpBuffer</i> - output memory buffer for the read data<br>
<i>nSize</i> - number of bytes to be read<br>
<i>lpNumberOfBytesRead</i> - pointer to a variable that receives number of read bytes<br>
<br>
<hr />
<h2>WriteProcessMemory64</h2>
BOOL WriteProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T <code>*</code>lpNumberOfBytesWritten);<br>
<br>
Behaviour similar to x86 version of <b>WriteProcessMemory()</b>, internally it uses x64 version of <b>NtWriteVirtualMemory()</b> from NTDLL.<br>
<br>
<i>hProcess</i> - handle of  the process,  can be  obtained by  standard x86 version of <b>OpenProcess()</b> function<br>
<i>lpBaseAddress</i> - base address of the region that will be written<br>
<i>lpBuffer</i> - input memory buffer with the data to write<br>
<i>nSize</i> - number of bytes that will be written<br>
<i>lpNumberOfBytesRead</i> - pointer to variable that receives number of written bytes<br>
<br>
<hr />
<h2>VirtualAllocEx64</h2>
DWORD64 VirtualAllocEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);<br>
<br>
Behaviour similar to x86 version of <b>VirtualAllocEx64()</b>, internally it uses x64 version of <b>NtAllocateVirtualMemory()</b> from NTDLL.<br>
<br>
<i>hProcess</i> - handle of the process, can be obtained by standard x86 version of <b>OpenProcess()</b> function<br>
<i>lpAddress</i> - desired base address of the region that will be allocated<br>
<i>dwSize</i> - size of the region that will be allocated<br>
<i>flAllocationType</i> - type of memory allocation<br>
<i>flProtect</i> - memory protection for the region<br>

<hr />
<h2>VirtualFreeEx64</h2>
BOOL VirtualFreeEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD dwFreeType)<br>
<br>
Behaviour similar to x86 version of <b>VirtualFreeEx64()</b>, internally it uses x64 version of <b>NtFreeVirtualMemory()</b> from NTDLL.<br>
<br>
<i>hProcess</i> - handle of the process, can be obtained by standard x86 version of <b>OpenProcess()</b> function<br>
<i>lpAddress</i> - base address of the memory region to free<br>
<i>dwSize</i> - size (in bytes) of the memory region to free<br>
<i>dwFreeType</i> - type of free operation (MEM_RELEASE, MEM_DECOMMIT)<br>
<br>
<hr />
<h2>GetThreadContext64</h2>
BOOL GetThreadContext64(HANDLE hProcess, <b>CONTEXT64<i>lpContext);</i>

Behaviour similar to x86 version of</b>GetThreadContext()<b>, internally it uses x64 version of</b>NtGetContextThread()<i>from NTDLL. Definition of <b>CONTEXT64 can be found in wow64ext.h file.</b></i>hProcess<i>- handle of the process, can be obtained by standard x86 version of <b>OpenProcess()</b> function</i><br>
<i>lpContext</i> - A pointer to a <i>CONTEXT64 structure that will receive context data from specified  thread. Structure will be filled according to ContextFlags field.</i>

<hr />
<h2>SetThreadContext64</h2>
BOOL SetThreadContext64(HANDLE hProcess, <b>CONTEXT64<i>lpContext);</i>

Behaviour similar to x86 version of</b>SetThreadContext()<b>, internally it uses x64 version of</b>NtSetContextThread()<i>from NTDLL. Definition of <b>CONTEXT64 can be found in wow64ext.h file.</b></i>hProcess<i>- handle of the process, can be obtained by standard x86 version of <b>OpenProcess()</b> function</i><br>
<i>lpContext</i> - A pointer to a 