rm -rf output
mkdir output

gcc target.c -shared -O0 -fPIC -fno-stack-protector -z-execstack -o output/target.so 
gcc encrypt.c -o output/encrypt
gcc runtime.c -ldl -o output/runtime

./output/encrypt output/target.so output/target.so.enc
./output/runtime output/target.so.enc