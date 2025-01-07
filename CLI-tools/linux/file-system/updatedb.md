
# `updatedb` Command
The `updatedb` command in Linux creates and updates a [DBMS](../../../coding/databases/DBMS.md) used by the `locate` command to find files. If the database already exists, then running `updatedb` will just update it rather than create the database.

The default database is stored at `/var/lib/plocate/plocate.db`. 
## Use
### Flags
#### `-o`
Give `updatedb` a file to store the generated database in (instead of the default which is `/var/lib/plocate/plocate.db`).
#### `--verbose`
Running this with `updatedb` will print all of the files in the database as they are discovered.
#### `--require-visibility`
This flag is used *when creating a database* (which can be done for different users by using the `-U` flag) to determine whether *any user can use `locate` to find files in the directories of other users* (whether or not they have permission to). 

Setting this to `0` or `no` means that any user, regardless of whether they own the directory, will see the contents of said directory when they use the `locate` or `plocate` commands. Unless the database is owned by `locate`/`plocate`, or the database file is *not* readable by others, then. any user will be able to see the files listed in the database using `locate`.

Setting this to `yes` or `1` (*which is the default*), then `locate` whill. *check the permissions* of the parent directories for each item *before reporting them* to the invoking user.

To create a private plocate database as a user other than root, run
              updatedb -l 0 -o db_file -U source_directory
       Note that all users that can read db_file can get the complete list of files in the subtree of source_directory.


       /etc/updatedb.conf
              A  configuration  file.  See updatedb.conf(5).  Uses exactly the same format as the one used by mlocate(1)'s updatedb,
              so they can be shared.

       /var/lib/plocate/plocate.db
              The database updated by default.

SECURITY
       Databases built with --require-visibility no allow users to find names of files and directories of other  users,  which  they
       would not otherwise be able to do.
