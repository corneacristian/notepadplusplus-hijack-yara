# Notepad++ Hijack Campaign 2026 YARA Rule

```
import "hash"

rule Notepad_Plus_Plus_Hijack
{
    meta:
        description = "Notepad++ Hijack Campaign"
        author = "Cristian Cornea"

    strings:
        $ioc1 = "95.179.213.0" ascii wide
        $ioc2 = "61.4.102.97" ascii wide
        $ioc3 = "59.110.7.32" ascii wide
        $ioc4 = "124.222.137.114" ascii wide
        $ioc5 = "api.skycloudcenter.com" ascii wide nocase
        $ioc6 = "api.wiresguard.com" ascii wide nocase

    condition:
        (
            hash.sha256(0, filesize) == "a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9" or // update.exe
            hash.sha256(0, filesize) == "8ea8b83645fba6e23d48075a0d3fc73ad2ba515b4536710cda4f1f232718f53e" or // [NSIS].nsi
            hash.sha256(0, filesize) == "2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924" or // BluetoothService.exe
            hash.sha256(0, filesize) == "77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e" or // BluetoothService
            hash.sha256(0, filesize) == "3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad" or // log.dll
            hash.sha256(0, filesize) == "9276594e73cda1c69b7d265b3f08dc8fa84bf2d6599086b9acc0bb3745146600" or // u.bat
            hash.sha256(0, filesize) == "f4d829739f2d6ba7e3ede83dad428a0ced1a703ec582fc73a4eee3df3704629a" or // conf.c
            hash.sha256(0, filesize) == "4a52570eeaf9d27722377865df312e295a7a23c3b6eb991944c2ecd707cc9906" or // libtcc.dll
            hash.sha256(0, filesize) == "831e1ea13a1bd405f5bda2b9d8f2265f7b1db6c668dd2165ccc8a9c4c15ea7dd" or // shellcode
            hash.sha256(0, filesize) == "0a9b8df968df41920b6ff07785cbfebe8bda29e6b512c94a3b2a83d10014d2fd" or // loader1
            hash.sha256(0, filesize) == "4c2ea8193f4a5db63b897a2d3ce127cc5d89687f380b97a1d91e0c8db542e4f8" or // uffhxpSy shellcode
            hash.sha256(0, filesize) == "e7cd605568c38bd6e0aba31045e1633205d0598c607a855e2e1bca4cca1c6eda" or // loader2
            hash.sha256(0, filesize) == "078a9e5c6c787e5532a7e728720cbafee9021bfec4a30e3c2be110748d7c43c5" or // 3yZR31VK shellcode
            hash.sha256(0, filesize) == "b4169a831292e245ebdffedd5820584d73b129411546e7d3eccf4663d5fc5be3" or // ConsoleApplication2.exe
            hash.sha256(0, filesize) == "7add554a98d3a99b319f2127688356c1283ed073a084805f14e33b4f6a6126fd" or // system shellcode
            hash.sha256(0, filesize) == "fcc2765305bcd213b7558025b2039df2265c3e0b6401e4833123c461df2de51a"    // s047t5g.exe
        )
        or any of ($ioc*)
}

```

Get YARA from here: https://github.com/VirusTotal/yara

## Usage
```
yara notepadplusplus.rule <Path to Search>
```



## References

1. https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
2. https://notepad-plus-plus.org/news/hijacked-incident-info-update/
3. https://github.com/CreamyG31337/chrysalis-ioc-triage

