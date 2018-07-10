// This is used to reverse engineer the code path/stacks used to generate a
// given sequence of code. From the sequence of code we first guess possible
// stacks for each bytes, then try to find consistent interpretations by looking
// at caller frames.

function asArrayBuffer(blob) {
    return new Promise(function (resolve, reject) {
        var fr = FileReader();
        fr.onload = function() {
            resolve(fr.response);
        };
        fr.readAsArrayBuffer(blob);
    });
}

function BufferIterator(buffer) {
    this.buffer = buffer;
    this.offset = 0;
    this.ptr_size = 8;
}
BufferIterator.prototype.setPtrSize = function (ptr_size) {
    this.ptr_size = ptr_size;
};
BufferIterator.prototype.asAscii = function(length) {
    var u8 = new Uint8Array(this.buffer, this.offset, length);
    this.offset += length;
    function copy(start, end) {
        if (end - start < 128)
            return String.fromCharCode.apply(null, u8.slice(start, end));
        var mid = (((end - start) / 2) | 0) + start;
        return copy(start, mid) + copy(mid, end)
    }
    return copy(0, length);
};
BufferIterator.prototype.asU8 = function() {
    var res = new DataView(this.buffer, this.offset, 1).getUint8();
    this.offset += 1;
    return res;
};
BufferIterator.prototype.asU32 = function() {
    var res = new DataView(this.buffer, this.offset, 4).getUint32();
    this.offset += 4;
    return res;
};
BufferIterator.prototype.asF64 = function() {
    var res = new DataView(this.buffer, this.offset, 8).getFloat64();
    this.offset += 8;
    return res;
};
BufferIterator.prototype.asPtr = function(ptr_size) {
    // Return pointers as string as we want to have value comparisons of tuples
    // of addresses.
    if (this.ptr_size == 4)
        return `ptr.${this.asU32()}`;
    return `ptr.${this.asU32()}.${this.asU32()}`;
};

function* range(max) {
    for (var i = 0; i < max; i++)
        yield i;
}

function readAddrToSymbols(reader) {
    var nb_names = reader.asU32();
    var ends_at = new Array(nb_names);
    var addr = new Array(nb_names);
    for (let i of range(nb_names)) {
        addr[i] = reader.asPtr();
        ends_at[i] = reader.asU32();
    }
    var allFrames = reader.asAscii(ends_at[nb_names - 1]);
    var starts_at = 0;
    var names = new Map();
    for (let i of range(nb_names)) {
        names.set(addr[i], allFrames.slice(starts_at, ends_at[i]));
        starts_at = ends_at[i];
    }
    return names;
}

function readByteToFrames(reader) {
    var bytes = new Array(256);
    for (let b of range(256)) {
        let nb_stacks = reader.asU32();
        let stacks = new Array(nb_stacks);
        for (let s of range(nb_stacks)) {
            let freq = reader.asF64();
            let nb_frames = reader.asU32();
            let frames = new Array(nb_frames);
            for (let f of range(nb_frames))
                frames[f] = reader.asPtr();
            stacks[s] = { freq, frames };
        }
        bytes[b] = stacks;
    }
    return bytes;
}

// This function returns to Map, one which for each (parent, child) will return
// a list of next-children, and one which for each child frame will return the
// list of parent frames.
function readStackAutomata(reader) {
    let nb_states = reader.asU32();
    console.log(`Graph: # states = ${nb_states}`);
    let states = [];
    for (let q of range(nb_states)) {
        let trans = {};
        let nb_trans = reader.asU32();
        for (let t of range(nb_trans)) {
            let edge = null;
            if (reader.asU8() == 0)
                edge = reader.asU8();
            else
                edge = reader.asPtr();
            let target = reader.asU32();
            trans[edge] = target;
        }
        states.push(trans);
    }
    let nb_final = reader.asU32();
    console.log(`Graph: # final = ${nb_final}`);
    let final_states = new Map();
    for (let f of range(nb_final)) {
        let state = reader.asU32();
        let nb_prod = reader.asU32();
        let produced = [];
        for (let p of range(nb_prod))
            produced.push(reader.asPtr());
        final_states.set(state, produced);
    }

    return { states, final_states };
}

async function decodeDb(url) {
    // Load the database
    var buffer = null;
    if (typeof fetch === "undefined") {
        buffer = os.file.readRelativeToScript(url, "binary").buffer;
    } else {
        var response = await fetch(url);
        if (!response.ok) {
            console.log("Failed to fetch database.");
            throw new Error("failed to fetch");
        }
        var blob = await response.blob();
        buffer = await asArrayBuffer(blob);
    }
    console.log(buffer.byteLength);
    var reader = new BufferIterator(buffer);

    // Check header code
    let offset = 0;
    let header_code = reader.asAscii(8);
    if (header_code != "SeqRec00") {
        console.log("Unexpected magic number: " + header_code)
        throw new Error("bad header code");
    }
    var ptr_size = reader.asU8();
    console.log("pointer size: " + ptr_size);
    reader.setPtrSize(ptr_size);

    // Read addresses to frames names mapping.
    console.log("read map of addresses to names.");
    var names = readAddrToSymbols(reader);

    // Read byte to stack frames mapping.
    console.log("Read byte to stacks mapping.");
    var bytes = readByteToFrames(reader);

    // Read per frame control flow.
    console.log("Read per frame control flow.");
    var { states, final_states } = readStackAutomata(reader);

    return { names, bytes, states, final_states };
}

function RevStack(state, next, ast) {
    this.state = state;
    this.next = next;
    this.ast = [];
    this.reduce_count = 0;
}
RevStack.prototype.clone = function () {
    return new RevStack(this.state, this.next, this.ast.slice());
}
function ParsedAttempt(stack, likely) {
    this.stack = stack;
    this.likely = likely;
}
ParsedAttempt.prototype.clone = function () {
    return new ParsedAttempt(this.stack.clone(), this.likely);
}

// A heap sort maintains a tree structure where the invariant is that the parent
// node is smaller than its children.
Array.prototype.insert_sorted = function (e, key, max_len) {
    var n = 0;
    var ekey = key(e);
    // First insert an element in a heap-sorted array.
    this.push(e);
    n = this.length;
    while (n > 1) {
        let i_elem = n - 1;
        let i_parent = (n / 2 - 1) | 0;
        if (key(this[i_parent]) <= ekey)
            break;
        var temp = this[i_elem];
        this[i_elem] = this[i_parent];
        this[i_parent] = temp;
    }
    // Remove the minimum from the array, move it to the top of the tree, and
    // make it sink toward the smallest (key-wise) child.
    if (this.length < max_len)
        return;
    n = 1;
    this[n - 1] = this.pop();
    while (true) {
        let i_head = n - 1;     // 0 indexed array
        let i_left = 2 * n - 1; // = (2 * n) - 1
        let i_right = 2 * n;    // = (2 * n + 1) - 1
        let k_head = key(this[i_head]);
        let k_left = i_left < this.length ? key(this[i_left]) : null;
        let k_right = i_right < this.length ? key(this[i_right]) : null;
        // No more children
        if (k_right == null && k_left == null)
            break;
        // No right childrem
        if (k_right == null) {
            // the head is smaller than its children
            if (k_head <= k_left)
                break;
            var temp = this[i_head];
            this[i_head] = this[i_left];
            this[i_left] = temp;
            n = i_left + 1;
            continue;
        }
        // The head is smaller than its children
        if (k_head <= k_left && k_head <= k_right)
            break;
        // The  smallest child is from the left.
        if (k_left < k_right) {
            var temp = this[i_head];
            this[i_head] = this[i_left];
            this[i_left] = temp;
            n = i_left + 1;
            continue;
        }
        // The smallest child is from the right.
        var temp = this[i_head];
        this[i_head] = this[i_right];
        this[i_right] = temp;
        n = i_right + 1;
    }
}

// Build an AST which is doing a fuzzy match of sequences.
function fuzzy_glr(input, { names, states, final_states }) {
    const shift_new_stack = 0.70;
    const shift_bit_error = 0.98;
    const shift_frame_error = Math.pow(shift_bit_error, 64);
    var stacks = [ new ParsedAttempt(new RevStack(0, null, []), 1) ];
    function key(a) { return a.likely; }
    const max_attempts = 256;
    const restart_threshold = Math.pow(shift_bit_error, 4096);
    let restart = 0;
    for (var i = 0; i < input.length; i++) {
        let token = input[i];
        var new_stacks = [];
        let nb_shift = 0, nb_reduce = 0;
        console.log("token:", token.toString(16));

        // (fuzzy-)Reduce: If we reached a final state, reduce it into a
        // token for the parent frame.
        for (var s = 0; s < stacks.length; s++) {
            let attempt = stacks[s];
            let final_frames = final_states.get(attempt.stack.state);
            if (!final_frames)
                continue;

            if (attempt.stack.reduce_count >= 50)
                continue;
            // console.log("    # final frame for", attempt.stack.state, "is", final_frames.length);
            for (let frame of final_frames) {
                let fork = attempt.clone();
                let ast = { frame, children: fork.stack.ast };
                if (!fork.stack.next)
                    fork.stack.next = new RevStack(0, null, []);
                fork.stack = fork.stack.next.clone();
                fork.stack.ast.push(ast);
                let edges = states[fork.stack.state];
                let next = edges[frame];
                if (!next)
                    continue;

                fork.stack.state = next;
                fork.stack.reduce_count = attempt.stack.reduce_count + final_frames.length;
                // console.log("  final frame:", attempt.stack.state, frame, fork.likely);
                nb_reduce++;
                stacks.push(fork);
            }
        }

        // (fuzzy-)Shift: Take all transition tokens and go to the next
        // state. Penalize all tokens which do not correspond to the input
        // sequence.
        for (let attempt of stacks) {
            // Skip the attempt if it is already below any attempt that we
            // already have in our list.
            if ((new_stacks.length >= max_attempts + 1 && attempt.likely < new_stacks[0].likely)
                || attempt.likely < restart_threshold)
                continue;

            // console.log('  start stack:', attempt.stack.state, attempt.likely);
            let edges = states[attempt.stack.state];
            let expectFrame = false;
            for (let edge of Object.keys(edges)) {
                let fork = attempt.clone();
                let error = false;
                fork.stack.state = edges[edge];
                if (edge.slice(0, 3) != "ptr") {
                    edge = edge | 0;
                    let same1 = edge & token; // same 1 at 1.
                    let same0 = edge | token; // same 0 at 0.
                    let diffBits = (same0 | ~same1) & 0xff; // different bits at 1.
                    let x = ((diffBits & 0xaa) >> 1) + diffBits & 0x55;
                    x = ((x & 0xcc) >> 2) + x & 0x33;
                    x = ((x & 0xf0) >> 4) + x & 0x0f;
                    if (x) {
                        fork.likely *= Math.pow(shift_bit_error, x);
                        error = true;
                    }
                } else {
                    expectFrame = true;
                    fork.likely *= shift_frame_error;
                    error = true;
                    // continue; // let's try avoiding these kind of errors.
                }
                fork.stack.ast.push({ byte: token, error });
                // console.log("    edge:", edge, fork.stack.state);
                nb_shift++;
                new_stacks.insert_sorted(fork, key, max_attempts);
            }
            if (expectFrame && states[0][token] !== undefined) {
                let fork = attempt.clone();
                fork.stack = new RevStack(0, fork.stack, [{byte: token, error: true}]);
                fork.stack.state = states[0][token];
                fork.likely *= shift_new_stack;
                // console.log("  expect frame:", fork.likely);
                nb_shift++;
                new_stacks.insert_sorted(fork, key, max_attempts);
            }

        }

        let likely_max = stacks.reduce((a, b) => Math.max(a, b.likely), 0);
        console.log('  (shift, reduce, likely) =', nb_shift, nb_reduce, likely_max);
        stacks = new_stacks;
        if (likely_max < restart_threshold) {
            stacks = [ new ParsedAttempt(new RevStack(0, null, []), 1) ];
            restart++;
            console.log("Restarting at offset", restart);
            i = restart;
        }
    }
    stacks.sort((a, b) => key(b) - key(a));
    console.log(stacks[0].likely, stacks[stacks.length - 1].likely);
    return stacks;
}

function astToString(ast, indent = 0) {
    var s = '';
    var byte = 0, b_cnt = 0;
    for (let token of ast) {
        if ("frame" in token) {
            s += "> ".repeat(indent) + frame + ":\n";
            s += printAst(token.children, indent + 1);
        } else {
            s += "> ".repeat(indent) + "0x" + token.byte.toString(16);
            s += (token.error ? "(error?)" : "") + "\n";
        }
    }
    return s;
}

async function seqRec(dbUrl, byteSequence) {
    try {
        var decoder = await decodeDb(dbUrl);
        var { names, bytes, states, final_states } = decoder;
    } catch(e) {
        console.log("error:" + e);
        throw e;
    }

    // Attempt to guess using bytes without any context.
    console.log("Attempt to guess each byte individually:");
    for (let b of byteSequence) {
        console.log("Read byte 0x" + b.toString(16));
        console.log(`  Found ${bytes[b].length} stacks:`);
        for (let stacks of bytes[b]) {
            console.log(`    Stacks (freq: ${stacks.freq})`);
            for (let frame of stacks.frames)
                console.log(`      frame: ${names.get(frame).replace(/\n/g, "\n       ")}`);
        }
    }

    // Attempt to guess using a fuzzy-glr parser.
    console.log("Attempt to guess using a fuzzy-glr parser:");
    /*
    var bits = [];
    for (let byte of byteSequence) {
        var mask = 128;
        while (mask) {
            var val = byte & mask;
            bits.push(val != 0 ? val : (~mask + 256));
            mask >>= 1;
        }
    }
    */
    var attempt = fuzzy_glr(byteSequence, { names, states, final_states })[0];
    console.log(attempt.likely);
    var s = attempt.stack;
    var s_ast = [];
    while (s != null) {
        s_ast.unshift(s.ast);
        s = s.next;
    }
    console.log(s_ast.length);
    for (let ast of s_ast)
        console.log(astToString(ast));
}

let test_sequence = [
    0xcc, 0xf4, 0xf4, 0xf4, 0xf4, 0xf4, 0xf4, 0xf4,
    0xf4, 0xf4, 0xf4, 0xf4, 0xf4, 0xf4, 0xf4, 0xf4,
    0xba, 0x20, 0x2f, 0xf8, 0x02, 0x48, 0x8b, 0x92,
    0xf8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x62, 0x70,
    0x68, 0xff, 0x00, 0x00, 0x00, 0x85, 0xc0, 0x0f,
    0x84, 0x2c, 0x00, 0x00, 0x00, 0x83, 0xf8, 0x01,
    0x0f, 0x84, 0xaa, 0x5f, 0x00, 0x00, 0xb8, 0x20,
    0x2f, 0xf8, 0x02, 0x48, 0x8b, 0xd4, 0x48, 0x83,
    0xe4, 0xf0, 0x52, 0x48, 0x83, 0xec, 0x08, 0x48,
    0x8b, 0xf8, 0xe8, 0x71, 0x60, 0x00, 0x00, 0x48,
    0x83, 0xc4, 0x08, 0x5c, 0xe9, 0x87, 0x5f, 0x00,
    0x00, 0x49, 0x8b, 0x21, 0x49, 0x8b, 0x41, 0x08,
    0x49, 0x8b, 0x49, 0x10, 0x48, 0x3b, 0xc1, 0x0f,
    0x86, 0x0f, 0x00, 0x00, 0x00, 0x48, 0x83, 0xe8,
    0x04, 0x48, 0x83, 0xec, 0x04, 0x8b, 0x10, 0x89,
    0x14, 0x24, 0xeb, 0xe8, 0x49, 0x8b, 0x51, 0x38,
    0x8b, 0x52, 0xe0, 0x48, 0xc1, 0xe2, 0x08, 0x48,
    0x83, 0xca, 0x21, 0x52, 0x41, 0xff, 0x71, 0x40,
    0xba, 0x20, 0x2f, 0xf8, 0x02, 0x48, 0x8b, 0x92,
    0xf8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x62, 0x70,
    0x68, 0xff, 0x00, 0x00, 0x00, 0x49, 0x83, 0x79,
    0x60, 0x00, 0x0f, 0x84, 0x3c, 0x00, 0x00, 0x00,
    0x41, 0xff, 0x71, 0x20, 0x41, 0xff, 0x71, 0x38,
    0x41, 0xff, 0x71, 0x40, 0x41, 0xff, 0x71, 0x60,
    0x48, 0x8b, 0xd4, 0x48, 0x83, 0xe4, 0xf0, 0x52,
    0x48, 0x83, 0xec, 0x08, 0x49, 0x8b, 0xf9, 0xe8,
    0xfc, 0x5f, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x08,
    0x5c, 0x85, 0xc0, 0x0f, 0x84, 0xff, 0x5e, 0x00,
    0x00, 0x5f, 0x5e, 0x5d, 0x59, 0x48, 0x83, 0xc4,
    0x18, 0x56, 0xff, 0x27, 0x41, 0xff, 0x71, 0x20,
    0x41, 0xff, 0x71, 0x30, 0x41, 0xff, 0x71, 0x38,
    0x41, 0xff, 0x71, 0x40, 0x48, 0x8b, 0xd4, 0x48
];

async function test() {
    try {
        await seqRec("./seqrec-out", test_sequence);
    } catch(e) {
        console.log("error: " + e +"\n" + e.stack)
    }
}

test();
