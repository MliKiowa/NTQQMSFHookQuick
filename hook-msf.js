// Windows X64 28418
let offset_recv = 0x1BD4802;
let offset_send = 0x1BD25E8;

function bytesToHex(arrayBuffer) {
    var bytes = new Uint8Array(arrayBuffer)
    for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
}
async function main() {
    let BaseMoudle = Module.findBaseAddress('wrapper.node');
    while (BaseMoudle == null) {
        BaseMoudle = Module.findBaseAddress('wrapper.node');
    }
    let hook_recv = BaseMoudle.add(offset_recv);
    console.log("hook_recv at: ", hook_recv);
    Interceptor.attach(hook_recv, {
        onEnter(args) {
            console.log('----------------------');
            let cmd = Memory.readPointer(args[1]).add(32).add(1);

            let seq = Memory.readPointer(args[1]).add(24);
            let uin = Memory.readPointer(args[1]).add(1);// remove error parse
            let bufferPtr =  Memory.readPointer(Memory.readPointer(args[1]).add(56));
            let buffer_start = Memory.readPointer(bufferPtr);
            let buffer_end = Memory.readPointer(bufferPtr.add(8));
            let buffer_len = buffer_end - buffer_start;
            let uin_str = Memory.readUtf8String(uin);

            if(isNaN(parseInt(uin_str))) uin_str = 'unknow';

            console.log('type: recv');
            console.log("seq:", Memory.readU32(seq));
            let _cmd = Memory.readUtf8String(cmd);
            if(_cmd.trim().length < 5) {
                _cmd =  Memory.readUtf8String(Memory.readPointer(Memory.readPointer(args[1]).add(48)));
            }
            console.log("cmd:",_cmd);
            console.log("uin:", uin_str);
            console.log("buffer_start:", buffer_start);
            console.log("buffer_ptr:", bufferPtr);
            console.log("buffer_end:", buffer_end);
            console.log("buffer_len:", buffer_len);
            console.log("hex buffer_start", bytesToHex(buffer_start.readByteArray(buffer_len)));
            console.log('----------------------');
        },
        onLeave(retval) {

        }
    })
    let hook_send = BaseMoudle.add(offset_send);
    console.log("hook_send at: ", hook_send);
    Interceptor.attach(hook_send, {
        onEnter(args) {
            console.log('----------------------');
            let seq = Memory.readPointer(args[1]).add(64);
            let uin = Memory.readPointer(args[1]).add(32).add(1);// remove error parse
            let uin_str =  Memory.readUtf8String(uin);
            let cmd = Memory.readPointer(Memory.readPointer(args[1])).add(1);// remove error parse
            let bufferPtr = Memory.readPointer(Memory.readPointer(Memory.readPointer(args[1])).add(32));
            let buffer_start = Memory.readPointer(bufferPtr);
            let buffer_end = Memory.readPointer(bufferPtr.add(8));
            let buffer_len = buffer_end - buffer_start;
            if(isNaN(parseInt(uin_str))) uin_str = 'unknow';

            console.log('type: send');
            console.log("seq:", Memory.readU32(seq));
            console.log("uin:",uin_str);
            let _cmd = Memory.readUtf8String(cmd);
            // if(_cmd.trim().length < 5) {
            //     _cmd =  Memory.readUtf8String(Memory.readPointer(Memory.readPointer(args[1])));
            // } 
            if(_cmd.trim().length < 5) {
                _cmd =  Memory.readUtf8String(Memory.readPointer(Memory.readPointer(Memory.readPointer(args[1])).add(16)));
            }
            console.log("cmd:",_cmd);
            console.log("buffer_start:", buffer_start);
            console.log("buffer_ptr:", bufferPtr);
            console.log("buffer_end:", buffer_end);
            console.log("buffer_len:", buffer_len);
            console.log("hex buffer_start", bytesToHex(buffer_start.readByteArray(buffer_len)));
            console.log('----------------------');
        },
        onLeave(retval) {
        }
    })
}

main().then();