Idea is simple:
Use a hashmap with names vectors to store all files contents, and then prints the duplicates
...

vector<vector<string>> findDuplicate(vector<string>& paths) {
    unordered_map<string, vector<string>> files;
    vector<vector<string>> result;

    for (auto path : paths) {
	    stringstream ss(path);
	    string root;
	    string s;
	    getline(ss, root, ' ');
	    while (getline(ss, s, ' ')) {
		    string fileName = root + '/' + s.substr(0, s.find('('));
		    string fileContent = s.substr(s.find('(') + 1, s.find(')') - s.find('(') - 1);
		    files[fileContent].push_back(fileName);
	    }
    }

    for (auto file : files) {
	    if (file.second.size() > 1)
		    result.push_back(file.second);
    }

    return result;
}
...
Follow up questions:

1. Imagine you are given a real file system, how will you search files? DFS or BFS ?
BFS can take advantage of the locality of files in inside directories, and therefore will probably be faster

2. If the file content is very large (GB level), how will you modify your solution?
In a real life solution we will not hash the entire file content, since it's not practical. Instead we will first map all the files according to size. Files with different sizes are guaranteed to be different. We will than hash a small part of the files with equal sizes (using MD5 for example). Only if the md5 is the same, we will compare the files byte by byte

3. If you can only read the file by 1kb each time, how will you modify your solution?
This won't change the solution. We can create the hash from the 1kb chunks, and then read the entire file if a full byte by byte comparison is required.

What is the time complexity of your modified solution? What is the most time consuming part and memory consuming part of it? How to optimize?
Time complexity is O(n^2 * k) since in worse case we might need to compare every file to all others. k is the file size

How to make sure the duplicated files you find are not false positive?
We will use several filters to compare: File size, Hash and byte by byte comparisons.

Thanks for writing this awesome answer and your response to the follow-up questions,
I just wanted to make up a few points that you missed:

MD5 is definitely one way to hash a file, another more optimal alternative is to use SHA256. Reference

Also, to answer this What is the most time consuming part and memory consuming part of it? How to optimize? part:
Comparing the file (by size, by hash and eventually byte by byte) is the most time consuming part.
Generating hash for every file will be the most memory consuming part. 
We follow the above procedure will optimize it, since we compare files by size first, only when sizes differ, we'll generate and compare hashes, and only when hashes are the same, we'll compare byte by byte.
Also, using better hashing algorithm will also reduce memory/time.
Reference:https://stackoverflow.com/questions/2722943/is-calculating-an-md5-hash-less-cpu-intensive-than-sha-family-functions
    
=========
"""
Dropbox

Duplicate Files

https://leetcode.com/problems/find-duplicate-file-in-system/

Given a file system, return a list of collections of duplicate files. 

Ask about:
Symbolic link, same file/dir with diff name, cannot detect cycle by visited...cycle?
-use absolute path/ skip symbolic link (if we search the whole file system)

What about invalid or malformed files e.g. permission or cannot read
-compare file by hashing (MD5, SHA)

If dir depth is large: DFS might stack overflow, use BFS; the variable to store pathname might overflow.
-Most memory consuming: MD5, read in files etc

What about race conditions, like if someone is writing the file while you are reading etc

What if the process takes a long time? 
-If error / hanging up in between: checkpoints, save states from time to time
"""

class DuplicateFiles:
    mb = 1024 * 1024

    def __init__(self, root):
        self.result = []
        self.size_to_files = {}
        self.root = root

    def get_hash(self, file):
        """Returns the SHA 256 hash of the file"""
        output_hash = hashlib.sha256()
        with open(file, "rb") as file_obj:
            mb_chunk = file_obj.read(mb)
            if mb_chunk is not None:
                output_hash.update(mb_chunk)
            else:
                break
        return output_hash.hexdigest()
    
    def add_file(self, file):
        if file.file_size in self.size_to_files:
            self.size_to_files[file.file_size].append(file)
        else:
            self.size_to_files[file.file_size] = [file]

    def group_files_by_size(self):
        """Populates self.size_to_files with the sizes and the files with those sizes"""
        queue = collections.deque()
        queue.appendleft(self.root)
        seen = set()
        while queue:
            current_folder = queue.pop()
            seen.add(current_folder)
            for content in current_folder.iter_dir(): #iterdir is the contents of the file, both files and folders
                if content.is_directory() and content not in seen:
                    queue.appendleft(content)
                    seen.add(content)
                elif content.is_file():
                    self.add_file(content)
                else:
                    #Ask the interviewer how to handle symlinks or special cases
                    pass

    def process_files(self):
        """Returns list of collections of duplicate files"""
        #First, group the files by size
        self.group_files_by_size()

        #Now you have the files grouped by size
        #For the sizes with more than one file, you need to deduplicate
        result = []
        for size, files in self.size_to_files.items():
            if len(files) > 1:
                hash_groups = {} #Map <hash: str, files with that hash: List[File]>
                for file in files:
                    file_hash = self.get_hash(file)
                    if file_hash in hash_groups:
                        hash_groups[file_hash].append(file)
                    else:
                        hash_groups[file_hash] = [file]
                for list_of_files in hash_groups.values():
                    if len(list_of_files) > 1:
                        result.append(list_of_files)
        return result

#Then call `duplicate_files = DuplicateFiles(root)` and `return duplicate_files.process()`
