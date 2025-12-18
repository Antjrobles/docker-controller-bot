
import re

def fix_indentation(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()

    fixed_lines = []
    for line in lines:
        # Count leading spaces
        match = re.match(r'^( +)', line)
        if match:
            spaces = match.group(1)
            # Replace 4 spaces with 1 tab
            tabs = spaces.replace('    ', '\t')
            # If there are remaining spaces (e.g. 2 spaces), keep them (alignment) or convert?
            # Assuming mixed content, let's just replace 4->1
            fixed_line = tabs + line[len(spaces):]
            fixed_lines.append(fixed_line)
        else:
            fixed_lines.append(line)

    with open(filename, 'w') as f:
        f.writelines(fixed_lines)

fix_indentation('docker-controller-bot.py')
print("Indentation fixed.")
