start_dir="/home/trshpuppy/repos/obsidian-notes"

move_out=$(cd ..)
move_home=$(cd $start_dir)

create_directories_file=ls -d */ > directories.txt
echo does dire .txt exist?
cat directories.txt
create_files_file=ls -F | grep -v / > files.txt

destroy_created_files=(rm files.txt && rm directories.txt)

echo "$(create_directories_file)"
echo "$(create_files_file)"

directories_ammount=$(cat directories.txt | wc -l)
echo number of dirs $directories_ammount
files_ammount=$(cat files.txt | wc -l)
echo number of files $files_ammount
echo 

echo the starting dir is $start_dir
echo

for dir in $(cat directories.txt); do
dir_name=$(echo $dir | cut -d '/' -f 1)
echo fixed dirname is $dir_name
echo
cd $dir_name

echo creating directories list...
"$(current_dir_directories)"
echo current directories\:
cat directories.txt
echo
echo creating file list...


done

