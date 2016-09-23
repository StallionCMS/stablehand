#!/usr/local/bin/ipython
import codecs
import os

def info(msg):
    print(msg)

def install(*args):
    cmd_args = ['apt-get', 'install', '-qq', '-y'] + list(args)
    if os.path.isfile('/usr/bin/apt-get'):
        info('Install if does not exist: apt-get install %s' % ' '.join(args))
        ![@(cmd_args)]
    else:
        raise Exception('apt-get does not exist on this system. Stablehand only supports ubuntu right now.')

def cp(source, dest, mode='644'):
    ![@(['cp', source, dest])]
    ![@(['chmod', mode, dest])]
        
def write(s, dest, mode='644'):
    if not os.path.isdir(os.path.dirname(dest)):
        raise Exception("Tried to write file '%s' but parent directory does not exist!" % dest)
    with codecs.open(dest, 'w', 'utf-8') as f:
         f.write(s)
    ![@(['chmod', mode, dest])]         

def substitute(existing_text, new_text, file_path):
    with codecs.open(file_path, 'r', 'utf-8') as f:
        content = f.read()
    if existing_text not in content:
        return False
    content = content.replace(existing_text, new_text)
    with codecs.open(file_path, 'w', 'utf-8') as f:
        f.write(content)
    return True

def write_exact(new_text, file_path, before_text=None):
    with codecs.open(file_path, 'r', 'utf-8') as f:
        content = f.read()
    if not new_text in content:
        if after_text:
            i = content.find(before_text)
            if i > -1:
                content = content[:i] + new_text + content[i:]
        else:
            content += new_text
    else:
        return False
    with codecs.open(file_path, 'w', 'utf-8') as f:
        f.write(content)
    return True
        

def write_line(line, dest, starts_with='', mode='644', matcher=None):
    '''
    Adds the passed in line to a file.

    If the file exists, and a line of the same pattern exists in the file, then replace the line with the new line
    If the file exists, and the line does not exist, add it to the end of the file

    @dest - the path of the file to append
    @line - the line to add
    @startswith - a simple string to match the starting pattern of the line
    @matcher - a compiled regex to match whether the line exists already
    
    '''
    if not os.path.isdir(os.path.dirname(dest)):
        raise Exception("Tried to write line to file '%s' but parent directory does not exist!" % dest)
    line = line.strip()
    if '\n' in line:
        raise Exception('argument @line must be a single line, with no newlines!')

    if not exists(dest):
        write(line + '\n', dest, mode=mode)
        return
    with codecs.open(dest, 'r', 'utf-8') as f:
        source = f.read()
    new_lines = []
    if not starts_with and not matcher:
        raise Exception('write_line must be called with either starts_with string or a compiled regex matcher!')
    found = False
    for existing_line in source.split('\n'):
        if matcher and matcher.match(existing_line):
            found = True
            new_lines.append(line)
        elif starts_with and line.startswith(starts_with):
            found = True
            new_lines.append(line)
        else:
            new_lines.append(existing_line)
    if not found:
        new_lines.append(line)
    source = '\n'.join(new_lines)
    write(source, dest, mode=mode)

exists = lambda path: os.path.isfile(path) or os.path.isdir(path)
