
# Relational Databases
RDBMS are the most common type of databases. They use a schema /template to dictate the structure and how the data is stored in the DB. Data is associated with keys which provide access to a specific row or column.

Tables or "entities" are all related to each other so a change in one will effect others but only in a predictable way.
![](/coding/coding-pics/DBMS-2.png)
In the image above,  the `id` related to users in the `users` table is the same as `user_id` used to relate to user posts in the `posts` table. This type of relationship is more efficient because, for example, not all data related to each user has to be stored with their posts.