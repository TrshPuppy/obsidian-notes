
# React Framework
Simplest React example:
```JSX
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<h1>Hello, world!</h1>);
```
Displays a heading which reads "Hello, world!".

## JSX:
```JSX
const element = <h1>Hello, worlds!</h1>;
```
#JSX is a syntax extension to JavaScript. It creates React "elements". JSX is used to "separate concerns" rather than separating *technologies* (like splitting markup from logic in a web application).

*JSX is not required for React but it makes it easier to read UI elements inline with JS code* and allows for error highlighting, etc.

After compilation, JSX expressions *become regular JavaScript* and evaluate into JS objects. This allows it to be used in if statements, for loops, be assigned to variables, and be accepted as arguments or returned from functions.

### Security:
React JSX ["helps prevent XSS"](https://reactjs.org/docs/introducing-jsx.html) because the JSX is turned into strings by the React DOM before being rendered.

## Hooks
### useEffect
https://beta.reactjs.org/reference/react/useEffect

### useState
https://beta.reactjs.org/reference/react/useState
