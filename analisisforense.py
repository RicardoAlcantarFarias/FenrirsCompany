import os
import sys 
import hashlib
import datetime

class ForensicTool:
    def __init__(self):
        self.case_id = ''
        self.evidence = []
    
    def start_case(self):
        self.case_id = input("Enter case ID: ")
        self.evidence = [] 
        print(f"Starting case with ID: {self.case_id}") 
        
    def add_evidence(self, evidence_path):
        if not os.path.exists(evidence_path):
            print(f"Evidence at {evidence_path} does not exist")
            return
            
        self.evidence.append(evidence_path)
        print(f"Added evidence at {evidence_path}")

    def analyze_files(self):
        print("Analyzing files...")
        suspicious_files = []
        
        for filepath in self.evidence:
            filename = os.path.basename(filepath)
            
            # Check hash against database of known malicious files
            file_hash = self.generate_hash(filepath)
            if self.check_malicious(file_hash):
                print(f"{filename} identified as malicious")
                suspicious_files.append(filepath)
                
            # Check timestamps  
            t = os.path.getmtime(filepath)
            filetime = datetime.datetime.fromtimestamp(t)  
            if self.check_suspicious_time(filetime):
                print(f"Suspicious timestamp on {filename}")
                suspicious_files.append(filepath)
                
        return suspicious_files
    
    def generate_hash(self, filepath):
        hash_md5 = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
                
    def check_malicious(self, file_hash): 
        # Logic to check hash against database
        return False  
    
    def check_suspicious_time(self, filetime):
        # Logic to check if timestamp is suspicious
        return False
        
if __name__ == "__main__":
    tool = ForensicTool()
    tool.start_case()
    tool.add_evidence('file1.txt')
    tool.add_evidence('malware.exe')
    tool.analyze_files()