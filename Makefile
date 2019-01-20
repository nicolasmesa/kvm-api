# Makeifle for vm

# List the object files in one place
OBJ=main.o

build: vm

vm: $(OBJ)
	cc -o $@ $(OBJ)
exec: build
	./vm $(ARG)

clean:
	rm -f vm *.o

