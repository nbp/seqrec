#!/bin/sh
#!nix-shell -i python3 -p python3 -p binutils
#
# binutils is used for addr2line, to lookup the symbols of the binary which is
# currently submitting stacks via the fifo.


# The beginning of this script is both valid shell and valid python, such that
# the script starts with the shell and is reexecuted with the right python.
#
# If nix is installed on your system, this script will pull the dependencies
# for it, as-if you were running in a virtual-env. Otherwise, it default to
# your local install of python.

'''echo' > /dev/null
which nix-shell > /dev/null && exec nix-shell "$0" "$@"
which python3 > /dev/null && exec python3 "$0" "$@"
exec python "$0" "$@"
'''

import argparse
import os
import struct
import re
import types
from subprocess import Popen, PIPE
from queue import Queue, Empty
from threading import Thread
from functools import reduce
from select import select
from itertools import accumulate

args_parser = argparse.ArgumentParser(description = 'Listen to a fifo an learn to associate byte sequences to stacks.')

# Option related to the binary.
args_parser.add_argument('--fifo', type = str, default = '/tmp/seqrec.fifo', help = 'File used for transfering content')
args_parser.add_argument('--binary', type = str, help = 'Binary which is sending content to this server')
args_parser.add_argument('--ptr-size', type = int, default = 8, help = 'Size of return addresses pointers')

# Option related to the output
args_parser.add_argument('--out', type = str, help = 'Classification file')
args_parser.add_argument('--single', action = 'store_true', help = 'Wait only for a single program execution')

# Options related to the recording
args_parser.add_argument('--byte-threshold', type = float, default = 0.05, help = 'threshold under which the stack are shrinked.')
args_parser.add_argument('--ignore-frames', type = int, default = 1, help = 'Number of frames to ignore at the top of the stack.')

args = args_parser.parse_args()

class StackRecord:
    ''' Record send by the various processes writting to the Fifo. '''
    def __init__(self, tid, data, frames):
        self.tid = tid       # Thread id
        self.data = data     # Bytes recorded
        self.frames = frames # Return addresses

class StackRecordParser:
    '''
      Iterator which iterate over the file content and output StackRecords as the
      file is being read.

      The fifo is containing a stream of data which is specified as follow:
        - thread-id (4 bytes)
        - num bytes (1 byte)
        - byte sequence (0-255 bytes)
        - stack depth (1 byte)
        - return addresses (4/8 * 0-255 bytes)
    '''
    def __init__(self, fd, ptr_size, ignore_frames):
        self.ptr_size = ptr_size
        self.ignore_frames = ignore_frames
        self.fd = fd

    def __iter__(self):
        return self

    def __next__(self):
        select([self.fd], [], [self.fd])
        tid = self.fd.read(4)
        # A zero thread ID is used as a way to stop the program.
        if tid == b'\x00\x00\x00\x00' or tid == b'':
            raise StopIteration
        else:
            return self.unpackData(tid)

    def unpackData(self, tid):
        num = ord(self.fd.read(1))
        data = []
        for _ in range(num):
            data.append(self.fd.read(1))
        depth = ord(self.fd.read(1))
        frames = self.fd.read(self.ptr_size * depth)
        if self.ignore_frames > 0:
            frames = frames[:-1 * self.ignore_frames * self.ptr_size]
        return StackRecord(tid, data, frames)


# When reading wthe stack records we create 2 classification methods:
#
#  1. A naive classifier, which for each byte recorded will associate a
#  likelyhood to a each stack. Unlikely stack are generalized by reducing the
#  stack depth.
#
#  2. A markov chain, which will record for each frame, the sequences of the
#  child frames.
#
# The naive classifier is used to give a guess for each byte, independently of
# the context in which each byte appears. The markov chain is used for doing
# some fuzzy matching among the list of stacks returned by the naive
# classifier.

def sentinel(head, iterator):
    yield head
    for value in iterator:
        yield value


class ByteClassifier:
    '''For each byte associate a list of stack and the number of occurences. This
      is used to give a first hint to what code might have generated each byte.
      Alone, this would generate a lot of noise as the number of bytes is
      extremelly limited compared to the number of possible stacks to generate
      each byte.

    '''
    def __init__(self, ptr_size, threshold):
        self.byteCounts = [ 0 for _ in range(256) ]
        self.byteStacks = [ [] for _ in range(256) ]
        self.ptr_size = ptr_size
        self.threshold = threshold

    def addRecord(self, record):
        for byte in record.data:
            self.addByte(ord(byte), record.frames)

    # Note: when recording, the frequency of a stack frame, we fake it to
    # be 1, and slowly make it converge towards the actual frequency. This
    # is done to avoid trashing newly added frames too early.
    def addByte(self, byte, frames):
        self.byteCounts[byte] += 1
        self.byteStacks[byte].append({
            'count': 1.0,
            'frames': frames
        })
        if self.byteCounts[byte] % 1000 == 0:
            self.balance(byte)

    # Balance the list of frames, and trash outermost frames of the stacks if
    # they are not frequent enough.
    def balance(self, byte):
        counts = self.byteCounts[byte]
        stacks = self.byteStacks[byte]
        while True:
            # Order sample by frames prefixes.
            def framesOf(entry):
                return entry['frames']
            stacks.sort(key = framesOf)

            # Fold identical frames.
            def foldFrames(l, e):
                if len(l) > 0 and l[-1]['frames'] == e['frames']:
                    l[-1]['count'] += e['count']
                else:
                    l.append(e)
                return l
            stacks = reduce(foldFrames, stacks, [])

            # Find the largest depth of frames which have a low threshold.
            low = filter(lambda e: e['count'] / counts < self.threshold, stacks)
            deepest = max(sentinel(0, map(lambda e: len(e['frames']), low)))
            if deepest == 0:
                break

            # Shrink the deepest frames which have low thresholds.
            def shrinkFrames(e):
                if len(e['frames']) == deepest and e['count'] / counts < self.threshold:
                    e['frames'] = e['frames'][:-(self.ptr_size)]
                return e
            stacks = list(map(shrinkFrames, stacks))

        self.byteStacks[byte] = stacks

    def finalize(self, out):
        for byte in range(256):
            self.balance(byte)
        for byte in range(256):
            stacks = self.byteStacks[byte]
            out.write(struct.pack('!L', len(stacks)))
            for sample in stacks:
                assert len(sample['frames']) % self.ptr_size == 0
                out.write(struct.pack('!dL', sample['count'] / self.byteCounts[byte], int(len(sample['frames']) / self.ptr_size)))
                out.write(sample['frames'])


class StackClassifier:
    '''For each stack frame, record the transition observed for the frames which
      are listed below. This is used to filter out stacks reported by the byte
      classifier in order to favor sequences of bytes which are likely.

      Note, the current implementation might fail to properly recover recursive functions.
    '''
    def __init__(self, ptr_size):
        self.ptr_size = ptr_size
        # Record the last frames for a given thread Id, in order to deduce
        # which frames are being finished, and which are being created.
        self.tid_last_frames = {}
        # Record state transitions based on bits or frames. Note, we use bits
        # instead of bytes because while bits might make the number of state
        # explose, we expect that many bits are going to represent variable
        # data and not valuable identifying data. This automata represent all
        # grammar rules necessary to reconstruct the stack frames.
        self.tid_last_states = {}
        self.nb_states = 1
        self.states = { 0: {} }
        # Note, the final state are recording which non-terminal (as a grammar
        # rule) are being produced.
        self.final_states = {}
        pass

    def addRecord(self, record):
        if (record.tid not in self.tid_last_frames) or (not self.tid_last_frames[record.tid]):
            new_frames = self.frameList(record.frames)
            self.tid_last_frames[record.tid] = new_frames
            self.tid_last_states[record.tid] = [ 0 for i in new_frames ]
            st = self.tid_last_states[record.tid]
            # Record each frame as an expected token for their parent frame.
            for i, child in zip(range(len(new_frames)), new_frames[1:]):
                st[i] = self.trans(st[i], child)
            # Record the bits sequences as expected token for the last frame.
            for byte in record.data:
                # for mask in [128,64,32,16,8,4,2,1]:
                #     bit = ord(byte) & mask
                #     if bit == 0:
                #         bit = ~mask + 256
                #     st[-1] = self.trans(st[-1], bit)
                st[-1] = self.trans(st[-1], ord(byte))
            assert len(self.tid_last_frames[record.tid]) == len(self.tid_last_states[record.tid])
            return

        # Get each frames as a list of frame pointers
        assert len(self.tid_last_frames[record.tid]) == len(self.tid_last_states[record.tid])
        last_frames = self.tid_last_frames[record.tid]
        new_frames = self.frameList(record.frames)
        st = self.tid_last_states[record.tid]

        # If the variation between the old stack frames and the new stack
        # frames are too large, consider the old stack frame as being ended,
        # and assume we started a new stack frame.
        delta = set(last_frames).symmetric_difference(set(new_frames))
        if len(delta) > len(new_frames) / 2:
            for i in range(len(last_frames)):
                self.fin(st[i], last_frames[i])
            self.tid_last_frames[record.tid] = None
            self.tid_last_states[record.tid] = None
            self.addRecord(record)
            assert len(self.tid_last_frames[record.tid]) == len(self.tid_last_states[record.tid])
            return

        # Update the recorded stack frames.
        self.tid_last_frames[record.tid] = new_frames

        # Remove varying bottom stacks (when reaching the max stack frames), in
        # order to align the stack frames.
        last_frames, last_rm = self.filterBottom(delta, last_frames)
        new_frames, new_rm = self.filterBottom(delta, new_frames)

        # Search for the first difference.
        common_len = min(len(last_frames), len(new_frames))
        diff_idx = common_len
        for i, o, n in zip(range(common_len), last_frames, new_frames):
            if o != n:
                diff_idx = i
                break

        # Last frame in common: Add a new transition to the last frame which is
        # common between the previous and the current frame.
        assert diff_idx >= 1
        if diff_idx < common_len:
            st[last_rm + diff_idx - 1] = self.trans(st[diff_idx - 1], new_frames[diff_idx])

        # Frames which are no longer on the stack: We reached the end of a
        # grammar rule, thus mark the last state as final state which produce
        # the frame necessary for the making the transition in the parent
        # frame.
        for i in range(diff_idx, len(last_frames)):
            self.fin(st[last_rm + i], last_frames[i])
        st = st[:last_rm + diff_idx]

        # Frames which are newly added on the stack: For each new frame start
        # over from the initial state. Register the child frame as the first
        # transition.
        for child in new_frames[diff_idx + 1:]:
            st.append(0)
            st[-1] = self.trans(st[-1], child)

        # Add bytes as bits transitions to move the state of the last frame.
        if diff_idx < len(new_frames):
            st.append(0)
        for byte in record.data:
            # for mask in [128,64,32,16,8,4,2,1]:
            #     bit = ord(byte) & mask
            #     if bit == 0:
            #         bit = ~mask + 256
            #     st[-1] = self.trans(st[-1], bit)
            st[-1] = self.trans(st[-1], ord(byte))

        self.tid_last_states[record.tid] = st
        assert len(self.tid_last_frames[record.tid]) == len(self.tid_last_states[record.tid])

    def trans(self, q, v):
        a = self.states[q]
        if v not in a:
            self.states[self.nb_states] = {}
            a[v] = self.nb_states
            self.nb_states += 1
        return a[v]

    def fin(self, q, produce):
        if q not in self.final_states:
            self.final_states[q] = set()
        self.final_states[q].add(produce)

    def frameList(self, frames):
        vec = []
        while len(frames) >= self.ptr_size:
            vec.append(frames[:self.ptr_size])
            frames = frames[self.ptr_size:]
        return vec

    def filterBottom(self, delta, frameList):
        cnt = 0
        while frameList[-1] in delta:
            frameList = frameList[:-1]
            cnt += 1
        return frameList, cnt

    def minimize(self):
        # TODO: Minimize the automata such that we reduce the number of states
        # and final states.
        # TODO: Approximate the automata,
        # such that we can add loops if we have really long chains of similar
        # transitions.
        pass

    def finalize(self, out):
        self.minimize()
        assert self.nb_states == len(self.states)
        out.write(struct.pack('!L', self.nb_states))
        for q in range(self.nb_states):
            edges = self.states[q]
            out.write(struct.pack('!L', len(edges)))
            for edge, target in edges.items():
                if type(edge) is int:
                    out.write(b'\x00')
                    out.write(struct.pack('B', edge))
                else:
                    out.write(b'\x01')
                    out.write(edge)
                out.write(struct.pack('!L', target))
        out.write(struct.pack('!L', len(self.final_states)))
        for state, produce in self.final_states.items():
            out.write(struct.pack('!LL', state, len(produce)))
            for frame in produce:
                out.write(frame)


class NameClassifier:
    '''Record the function names of each frames not by calling addr2line on the binary
      ask we discover new frames.

    '''
    def __init__(self, binary, ptr_size):
        self.names = set()
        self.binary = binary
        self.ptr_size = ptr_size

    def addRecord(self, record):
        frames = record.frames
        while len(frames) != 0:
            frame = frames[:self.ptr_size]
            self.names.add(frame)
            frames = frames[self.ptr_size:]

    def finalize(self, out):
        # Pipe the list of addresses through addr2line to resolve all symbols.
        addr2line = Popen(['addr2line', '-spaCife', self.binary], stdin=PIPE, stdout=PIPE)
        literal_addrs = ''
        for addr in self.names:
            rev = [a for a in addr]
            rev.reverse()
            addr = bytes(rev)
            literal_addrs += '0x%s\n' % addr.hex()
        res, err = addr2line.communicate(input = bytes(literal_addrs, 'ascii'))
        # Split addr2line output by addresses.
        extract = re.compile(r"0x(?P<addr>[0-9a-f]+): (?P<stack>.*\n(?:.*inlined by.*\n)*)", re.MULTILINE)
        frames = [bytes(f.group('stack'), 'ascii') for f in re.finditer(extract, str(res, 'ascii'))]
        out.write(struct.pack('!L', len(self.names)))
        for addr, ends_at in zip(self.names, accumulate(map(len, frames))):
            out.write(addr)
            out.write(struct.pack('!L', ends_at))
        out.write(b''.join(frames))
        addr2line.stdin.close()


class AggregateClassifier:
    '''Aggregate data into multiple classifiers.'''
    def __init__(self, classifiers):
        self.classifiers = classifiers

    def addRecord(self, record):
        for c in self.classifiers:
            c.addRecord(record)

    def finalize(self, out):
        for c in self.classifiers:
            c.finalize(out)


# Top level logic for reading the Fifo, and serializing the data in a file.

def listenForData(fifo, ptr_size, ignore_frames, classifiers, out):
    os.mkfifo(fifo)
    if not args.single:
        keep_alive = Popen('while sleep 3600; do :; done > ' + fifo, shell = True)
    with open(fifo, mode='rb') as fd:
        for i, record in enumerate(StackRecordParser(fd, ptr_size, ignore_frames)):
            print("\rRecord %d from thread %d, %d byte(s), %d frames" % (i, struct.unpack('I', record.tid)[0], len(record.data), len(record.frames) / ptr_size), end='', flush=True)
            classifiers.addRecord(record)
    if not args.single:
        keep_alive.kill()
        keep_alive.communicate()
    os.unlink(fifo)
    print("\nWritting output file")
    with open(out, mode="wb") as output:
        output.write(b'SeqRec00')
        output.write(struct.pack('B', ptr_size))
        classifiers.finalize(output)


cl = []
cl.append(NameClassifier(args.binary, args.ptr_size))
cl.append(ByteClassifier(args.ptr_size, args.byte_threshold))
cl.append(StackClassifier(args.ptr_size))
cl = AggregateClassifier(cl)
listenForData(args.fifo, args.ptr_size, args.ignore_frames, cl, args.out)
