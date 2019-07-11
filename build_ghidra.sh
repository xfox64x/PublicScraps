# https://github.com/NationalSecurityAgency/ghidra/blob/master/DevGuide.md

rm -rf ~/git/ghidra
rm -rf ~/git/ghidra.bin
mkdir -p ~/git
cd ~/git
git clone https://github.com/NationalSecurityAgency/ghidra.git
mkdir -p ~/flatRepo
printf "ext.HOME = System.getProperty('user.home')\nallprojects {\n\trepositories {\n\t\tmavenCentral()\n\t\tjcenter()\n\t\tflatDir name:'flat', dirs:[\"$HOME/flatRepo\"]\n\t}\n}\n" > ~/.gradle/init.d/repos.gradle
if [ ! -f ~/flatRepo/dex-writer-2.0.jar ]; then
        cd ~/Downloads
        if [ ! -f ~/Downloads/dex-tools-2.0.zip ]; then
                curl -OL https://github.com/pxb1988/dex2jar/releases/download/2.0/dex-tools-2.0.zip
                unzip dex-tools-2.0.zip
        fi
        cp ~/Downloads/dex2jar-2.0/lib/dex-*.jar ~/flatRepo/
fi
if [ ! -f ~/flatRepo/AXMLPrinter2.jar ]; then
        cd ~/flatRepo
        curl -OL https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/android4me/AXMLPrinter2.jar
fi
if [ ! -f ~/flatRepo/hfsx.jar ]; then
        if [ ! -f ~/Downloads/hfsx/lib/csframework.jar ]; then
                cd ~/Downloads
                curl -OL https://sourceforge.net/projects/catacombae/files/HFSExplorer/0.21/hfsexplorer-0_21-bin.zip
                mkdir hfsx
                cd hfsx
                unzip ../hfsexplorer-0_21-bin.zip
        fi
        cd ~/Downloads/hfsx/lib
        cp csframework.jar hfsx_dmglib.jar hfsx.jar iharder-base64.jar ~/flatRepo/
fi
if [ ! -f ~/git/ghidra.bin/Ghidra/Features/GhidraServer/yajsw-stable-12.12.zip ]; then
        if [ ! -f ~/Downloads/yajsw-stable-12.12.zip ]; then
                cd ~/Downloads
                curl -OL https://sourceforge.net/projects/yajsw/files/yajsw/yajsw-stable-12.12/yajsw-stable-12.12.zip
        fi
        mkdir -p ~/git/ghidra.bin/Ghidra/Features/GhidraServer/
        cp ~/Downloads/yajsw-stable-12.12.zip ~/git/ghidra.bin/Ghidra/Features/GhidraServer/
fi
cd ~/git/ghidra
gradle buildNatives_linux64
gradle yajswDevUnpack
gradle buildGhidra
mkdir -p ~/git/ghidra_builds
cp ~/git/ghidra/build/dist/* ~/git/ghidra_builds
