
# Vim: CLI Text Editor
**[Ultimate Cheat Sheet](https://vim.rtorr.com)**
## Quick Cheats:
#### Replace multiple instances or same word:
1. type `/<word to replace>` & press `Enter` (cursor jumps to first occurence)
2. in `NORMAL` mode type `cgn` (word gets deleted)
3. type in the new word, then press `Esc` (`NORMAL` mode)
4. use `n` or `N` to jump to the next or previous occurrence of the original word
5. press `.` and the current word will be replaced with the new word you used to replace the first occurrence
#### Move cursor to end/ start of line
In normal mode, press `0` to move the cursor to the start of the current line. Press `Shift` + `$` to move cursor to end of line.
## Config/ Settings
### Home Directory
Make the following folders in your home direcetory:
```bash
.vim/
 ├── autoload/
 ├── backup/
 ├── colors/
 └── plugged/
```
Then, create a `.vimrc` file in your home directory:
#### `~/.vimrc`:
This is the configuration file for vim. Double quotes (`"`) Create comments:
```vimrc
" Set shift width to 4 spaces.
set shiftwidth=4

" Set tab width to 4 columns.
set tabstop=4

" Use space characters instead of tabs.
set expandtab

" Do not save backup files.
set nobackup

" Do not let cursor scroll below or above N number of lines when scrolling.
set scrolloff=10

" Do not wrap lines. Allow long lines to extend as far as the line goes.
set nowrap

" While searching though a file incrementally highlight matching characters as you type.
set incsearch

" Ignore capital letters during search.
set ignorecase

" Override the ignorecase option if searching for capital letters.
" This will allow you to search specifically for capital letters.
set smartcase

" Show partial command you type in the last line of the screen.
set showcmd

" Show the mode you are on the last line.
set showmode

" Show matching words during a search.
set showmatch

" Use highlighting when doing a search.
set hlsearch

" Set the commands to save in history default number is 20.
set history=1000
```
>	[Free Code Camp](https://www.freecodecamp.org/news/vimrc-configuration-guide-customize-your-vim-editor/)
### Make default editor
```bash
sudo update-alternatives --config editor
```
### Folding
Folding in vim allows you to hide chunks of text. You can set fold manually or automatically. Folding text doesn't alter it, *however* you can alter (copy, paste, delete) text inside a fold by doing so while it is folded into a single line.
#### Manual folding
Use `:set foldmethod=manual` to manually tell Vim where to fold. Otherwise, Vim will try to figure out the folds on its own.

To set them manually, go to the line where you want your fold to begin. While in normal mode, use `Shift V` to select all the lines you want to fold.

Once they're all selected, use `zf` to fold them. Now, when your cursor is on the fold in normal mode, you can use `zo` and `zc` to open and close the fold.
#### Open and Closing
While `zo` and `zc` can open single folds, using `zr` and `zm` will open and close all of the folds in a file.

`za` is like a toggle. While your cursor is on a fold, hitting `za` will open or close it depending on which state it's already in.
#### Fold Methods (auto folding)
You can tell Vim how to decide when and where to fold. For example, when looking at code in Vim, you want it to fold based on the language's syntax.

There are a few fold methods you can tell Vim to use:
- `indent`: folds based on indentation, *works well for most coding languages*
- `syntax`: fold based on syntax (which is defined in the syntax files)
- `marker`: fold based on a specific marker found in the text
- `expr`: fold each line based on a given function
##### Giving Vim a default fold method:
In `.vimrc` you can tell Vim to use a default fold method by adding a line like this:
```.vimrc
set foldmethod=indent
```
##### Setting fold methods for specific contexts:
Even though the `indent` method is good for most coding languages, you might want certain filetypes to fold differently. To change the fold method for the `.vimrc` file itself you can use an `autocmd` to override the default in certain contexts:
```.vimrc
autocmd FileType vim setlocal foldmethod=marker
```
#### Fold Expressions
You can further customize your fold settings using fold expressions which are functions that help Vim decide how to fold.

To do this, you write a function and then use `autocmd` w/ the `foldexpr` set to your function to override the current fold settings in your specific case:
```.vimrc
autocmd FileType javascript foldmethod=expr
autocmd FileType javascript foldexpr=JSFolds()

function! JSFolds()
	let thisline = getline(v:lnum)
	if thisline =~? '|v^\s*$'
		return '-1'
	endif

	if thisline =~ '^import.*$'
		return 1
	else
		return indent(v:lnum) / &shiftwidth
	endif
endfunction
```
>	[Vim From Scratch](https://www.vimfromscratch.com/articles/vim-folding)

In this function, every line of the current file is read. If the line is empty (matching the first regex which is just matches any number of spaces), the function returns `-1`.

If the current line matches an `import` line of a JS file, the function returns `1`.

Otherwise, the function returns that Vim should follow the `indent` fold method and gives Vim the current indent level of that line
## Mapping Keyboard Shortcuts
In the `MAPPINGS` section of your `.vimrc` you can add key mappings. The syntax looks like this:
```.vimrc
<map mode> <they key you type> <what the key executes>
```
### Map Modes
The `map_mode` of the key mapping syntax determines what mode in Vim the keymapping will be applied to. The common ones are:
- `nnoremap`: Map keys in normal mode
- `inoremap`: Map keys in insert mode
- `vnoremap`: Map keys in visual mode
#### Example
Mapping `jj` to `ESC` in insert mode:
```.vimrc
inoremap jj <esc>
```

> [!Resources:]
> - [Linux Handbook](https://linuxhandbook.com/move-start-end-line-vim/)
> - [Linux Handbook: Vim Basics](https://linuxhandbook.com/basic-vim-commands/)
> - [Free Code Camp: Vimrc Config Guide](https://www.freecodecamp.org/news/vimrc-configuration-guide-customize-your-vim-editor/)
> - [Vim From Scratch: Folding](https://www.vimfromscratch.com/articles/vim-folding)
> - [Dev.to: Vim Keymappings](https://dev.to/mr_destructive/vim-keymapping-guide-3olb)
> - [Vim.rtoor: Vim Cheat Sheet](https://vim.rtorr.com)

