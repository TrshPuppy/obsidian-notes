
# GraphQL
GraphQL is a query language and a runtime used to queries APIs for *existing* data. It is not tied to any [databases](/coding/databases/DBMS.md) and instead is backed by your own code and data. 

## Usage:
GraphQL is a *server-side* runtime you can use to execute queries on your data. It allows you to define the queries which can be used via a type system.

You create a GQL service by defining types and fields on those types. Then you provide a function for each field:
```json
type Query{
	me: User
}

type User{
	id: ID
	name: String
}
```
This code block is an example of a *GraphQL service* which tells you who the logged in user is. An example of functions which can be written for each field in this query looks like this:
```js
function Query_me(request) {
	return request.auth.user
}

function User_name(user) {
	return user.getName()
}
```
Once created, a GQL service can be ran (usually at a URL of a website). From here it receives queries, validates, then executes them. 

### Validation:
Before executing the functions associated with a received query, GQL makes sure the query refers to only types and fields which have been defined in the service.

GraphQL uses its *type system* to validate incoming queries. Queries have to query for fields which are valid/defined on the given type. If the requested field does not exist, GQL will return an error:
```js
// Query (invalid):
{
  hero {
    favoriteSpaceship
  }
}

// Response (from GQL):
{
  "errors": [
    {
      "message": "Cannot query field \"favoriteSpaceship\" on type \"Character\".",
      "locations": [
        {
          "line": 4,
          "column": 5
        }
      ]
    }
  ]
}
```
There are many other types of errors that can arise when querying GQL. The types system helps to catch them and alert the developers that the service received invalid queries.

### Execution:
Once the query is validated, the functions attached to the types and fields (defined in the service) are executed. GQL *cannot execute a query w/o a type system.*

#### Root fields & resolvers:
Each field in a query can be though of as a function/method of its parent type. These methods are called *resolvers*. Resolvers *return the next type in the chain.* When a field is executed, the corresponding resolver is called *to produce the next value*.

The top level of every GQL server *is a type that represents all possible entry points into the API*. It's called the "root type" or 'query type'.
```js
Query: {
	human(obj, args, context, info) { 
		return context.db.loadHumanByID(args.id).then(
		userData => new Human(userData)      
		)    
	}  
}     
```
This is an example of a resolver function written for the root query. In this example, the function retrieves a `Human` object and returns it.

#### Resolver syntax:
Resolvers are made up of four arguments and can be written in many different coding languages:
- `obj`: This is the previous object. Not normally used for a field on the root query type.
- `args`: These are the arguments provided to the field in the original query.
- `context`: a value provided to *every resolver*. It contains contextual information like the current logged in user, access to a database, etc..
- `info`: a value with field-specific info which is relevant to the current query + schema details.

### Results:
The result of executing a query is typically in [JSON](/coding/data-structures/JSON.md) format. The result normally attempts to mirror the original request:
```js
// OG ("root") Query:
{
  human(id: 1002) {
    name
    appearsIn
    starships {
      name
    }
  }
}

// JSON result:
{
  "data": {
    "human": {
      "name": "Han Solo",
      "appearsIn": [
        "NEWHOPE",
        "EMPIRE",
        "JEDI"
      ],
      "starships": [
        {
          "name": "Millenium Falcon"
        },
        {
          "name": "Imperial shuttle"
        }
      ]
    }
  }
}
```


> [!Resources]
> - [GraphQL: Intro to GraphQL](https://graphql.org/learn/)
> - [GQL: Validation](https://graphql.org/learn/validation/)
> - [GQL: Execution](https://graphql.org/learn/execution/)