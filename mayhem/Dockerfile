FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang

COPY . /repo
WORKDIR /repo
RUN make -j8
RUN clang ./mayhem/fuzz_ascii_strcmp_icase.c -fsanitize=fuzzer,address -I /repo/src/ -std=c99 /repo/src/util/ascii.c -o /fuzz

FROM ubuntu:22.04
COPY --from=builder /repo/dte /
COPY --from=builder /fuzz /fuzz_ascii_strcmp_icase