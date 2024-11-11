SRC=ldd.c 

CC:=gcc

all:
	$(CC) $(SRC) -o  lddw.exe -lshlwapi

clean:
	del *.exe