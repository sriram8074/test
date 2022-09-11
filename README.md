# test

Groups
1 Hit the below API which will give u the Group List
http://localhost:4502/bin/querybuilder.json?property=jcr:primaryType&property.value=rep:Group&limit=-1

2 Take each group link and hit with add the infinity.json
http://localhost:4502/home/groups/a/analytics-administrators.infinity.json

in output will get the members of user list whcih contain UUId of user.


3 Get the details of user need to hit another api take the UUid and hit below api

http://localhost:4502/bin/querybuilder.json?property=jcr:uuid&property.value=21232f29-7a57-35a7-8389-4a0e4a801fc3&p.limit=-1

will get link of user

4 will hit that link with infinity.json

http://localhost:4502//home/users/_/_GjWtsXhfrkKwjq7Ef-O.infinity.json
