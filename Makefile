all : clean probe.out run

run : probe.out

	echo 
	sudo ./probe.out

probe.out : probe.c

	gcc -o probe.out probe.c 

clean :

	rm -f probe.out
	rm -f probe_output_*
	clear
