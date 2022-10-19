# PcaSvc Proxy

Use Pca process as a proxy to do Read and Write calls on protected processes.

## How does it work?

#### 1. Get PcaSvc svchost.exe process id.
#### 2. Get a PROCESS_ALL_ACCESS handle to PcaSvc.
#### 3. Find the address that holds the handle to the target process, this must be done remotely as Pca has Strict handle checks
#### 4. Allocate a PAGE_EXECUTE_READWRITE memory region to write the shell code and the request object.
#### 5. Allocate two memory pages to pass read and write buffers to the shell code.
#### 6. Create a remote thread on the shell code base address.
#### 7. Use proxy::rvm and proxy::wvm

## License
[MIT](https://choosealicense.com/licenses/mit/)
