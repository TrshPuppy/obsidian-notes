
# JavaScript
INIT.
JS is a high-level coding language which was specifically designed and created for the web. All modern browsers have a built-in *JavaScript engine* which runs JS code from w/i the browser. When a browser renders a webpage (which the webpage serves as an [HTTP](../../www/HTTP.md) response usually containing [HTML](../../cybersecurity/bug-bounties/hackerone/hacker101/HTML.md)) the browser creates the [DOM](../../www/DOM.md) tree as a virtual representation of it. 

The DOM is comprised of every HTML element on the page. JavaScript is used to *access and modify the DOM* which results in a more interactive user-experience (as opposed to a "static" one). This also means that if JavaScript can be *injected into the DOM* maliciously, an attacker can gain access to the DOM and modify it as well. 
## The Language
### Objects
JavaScript is *Object Oriented*, meaning it's designed and written around "objects." Objects can be thought of as literal objects which have unique properties. For example, a puppy is an object and one of it's properties is that the puppy is "fluffy." 

If we were to represent a puppy object in JS code, it might look like this:
```js
const puppy = {
	fluffy: true,
	cute: true,
	color: "tan",
	name: "Loki"
}
```
Each property (like `fluffy`) describes our puppy object. If we wanted to check what our puppy object's name is, we would access that property like this:
```js
const puppysName = puppy.name

console.log(puppysName)

// output:
"Loki"
```
#### Methods
Objects can also have "methods." Methods are king of like properties, but they actually *do something*. That's because they are functions. These functions are called "methods" because they are attached to an object. For example, let's add a method to our puppy object. In our code, when we want our puppy to "bark," we can call (or execute) the object's `bark` method:
```js
const puppy = {
	fluffy: true,
	cute: true,
	color: "tan",
	name: "Loki"

	bark: function (){
		return "WOOF!"
	}
}
```
Now, for our puppy to bark, we have to call the `bark` property:
```js
const puppysBark = puppy.bark()

console.log(puppysBark)

// output:
"WOOF!"
```

> [!Resources]
> - [MDN](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object)
> - [My bren]()
