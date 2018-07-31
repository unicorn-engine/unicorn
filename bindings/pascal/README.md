# unicorn-engine-pascal

Pascal/Delphi language binding for the [Unicorn emulator](http://www.unicorn-engine.org/)
([GitHub](https://github.com/unicorn-engine/unicorn)).

*Unicorn* is a lightweight multi-platform, multi-architecture CPU emulator framework
based on [QEMU](http://www.qemu.org/).

## License

`GPLv2`

## Compilers Compatibility

#### Free Pascal >= v3 
  - `Mac OS` 
  - `Windows` 
  - `Linux`
#### Delphi
  - `Windows`
## Features

* Same API as the C core 
  - with some workarounds for Pascals case insensitivity: 


    `uc_mem_write()` -> `uc_mem_write_()`, `uc_mem_read()` -> `uc_mem_read_()`
  - and the missing feature passing variable number of arguments to functions (`...`): 
    
    i solve it by using -> `args : Array of Const;` 
    you can pass args inside [] like :
    ```pascal
    uc_hook_add(uc, trace, UC_HOOK_INSN, @HookIn, nil, 1,0,[UC_X86_INS_IN];
    ```
    the main loader in `Unicorn_dyn.pas` , check X86 example for more info .


* Multiplatform (Mac OS , Windows and Linux are tested)

## Examples
* `X86` Emulate 16, 32, 64 Bit x86


## Version History
* `1.1`
    * Add Delphi Compatibility [ Windows ]
* `1.0`
    * this is the first version it has all APIs of UNICORN v1.0.1

## TODO
  - Add more Examples
  - Add <b>Mac , Linux</b> Support for Delphi