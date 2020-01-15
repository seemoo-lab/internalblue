#!/bin/env sh
line=$(head -n 1 "$1")

if [[ $line == \#* ]] ;
then

	python -m internalblue.cli --device hci0 --replay "$1" --commands "$(echo $line | tr -d "#"); quit" 2>&1 | grep AssertionError || exit 0 && exit 1
else
	echo "Trace $1 has no command specified"
fi


