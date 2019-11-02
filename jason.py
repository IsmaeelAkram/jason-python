import os
import sys
import hashlib
import argparse 
import datetime

class Jason:

    def __init__(self):
        pass

    def characterize(string):
        return [char for char in string]

    def detect_hash(hash):
        if(len(hash) == 32):
            hashmethod = 'md5'
        elif(len(hash) == 40):
            hashmethod = 'sha1'
        elif(len(hash) == 64):
            hashmethod = 'sha256'
        elif(len(hash) == 96):
            hashmethod = 'sha384'
        elif(len(hash) == 128):
            hashmethod = 'sha512' 
        else:
            hashmethod = 'none'
        return hashmethod

    def commence():
        print(f"Starting attack | {datetime.datetime.now()}")

    @staticmethod
    def brute(hash):
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 !@#$%^&*;"
        hashmethod = Jason.detect_hash(hash)
        if(hashmethod == 'none'):
            print('Hash type not detected. Aborting.')
            return None
        else:
            print(f'Hash type detected: {hashmethod.upper()}')
        Jason.commence()
        while True:
            for l in alphabet:
                if(hashlib.md5(l.encode('utf-8')).hexdigest() == hash):
                    return l
            for l in alphabet:
                for l2 in alphabet:
                    if(hashlib.md5(f'{l}{l2}'.encode('utf-8')).hexdigest() == hash):
                        return l + l2
            for l in alphabet:
                for l2 in alphabet:
                    for l3 in alphabet:
                        if(hashlib.md5(f'{l}{l2}{l3}'.encode('utf-8')).hexdigest() == hash):
                            return l + l2 + l3
            for l in alphabet:
                for l2 in alphabet:
                    for l3 in alphabet:
                        for l4 in alphabet:
                            if(hashlib.md5(f'{l}{l2}{l3}{l4}'.encode('utf-8')).hexdigest() == hash):
                                return l + l2 + l3 + l4    
            for l in alphabet:
                for l2 in alphabet:
                    for l3 in alphabet:
                        for l4 in alphabet:
                            for l5 in alphabet:
                                if(hashlib.md5(f'{l}{l2}{l3}{l4}{l5}'.encode('utf-8')).hexdigest() == hash):
                                    return l + l2 + l3 + l4 + l5
            for l in alphabet:
                for l2 in alphabet:
                    for l3 in alphabet:
                        for l4 in alphabet:
                            for l5 in alphabet:
                                for l6 in alphabet:
                                    if(hashlib.md5(f'{l}{l2}{l3}{l4}{l5}{l6}'.encode('utf-8')).hexdigest() == hash):
                                        return l + l2 + l3 + l4 + l5 + l6
            for l in alphabet:
                for l2 in alphabet:
                    for l3 in alphabet:
                        for l4 in alphabet:
                            for l5 in alphabet:
                                for l6 in alphabet:
                                    for l7 in alphabet:
                                        if(hashlib.md5(f'{l}{l2}{l3}{l4}{l5}{l6}{l7}'.encode('utf-8')).hexdigest() == hash):
                                            return l + l2 + l3 + l4 + l5 + l6 + l7
            for l in alphabet:
                for l2 in alphabet:
                    for l3 in alphabet:
                        for l4 in alphabet:
                            for l5 in alphabet:
                                for l6 in alphabet:
                                    for l7 in alphabet:
                                        for l8 in alphabet:
                                            if(hashlib.md5(f'{l}{l2}{l3}{l4}{l5}{l6}{l7}{l8}'.encode('utf-8')).hexdigest() == hash):
                                                return l + l2 + l3 + l4 + l5 + l6 + l7 + l8
        
    @staticmethod
    def dictionary_attack(hash, passlist):
        hashmethod = Jason.detect_hash(hash)
        
        if(hashmethod == 'none'):
            print('Hash type not detected. Aborting.')
            return None
        else:
            print(f'Hash type detected: {hashmethod.upper()}')
        
        for password in passlist:
            if(hashmethod == 'md5'):
                newhash = hashlib.md5(password.encode('utf-8')).hexdigest()
                if newhash == hash:
                    return password
                elif newhash.upper() == hash:
                    return password
                elif newhash.lower() == hash:
                    return password
            if(hashmethod == 'sha1'):
                newhash = hashlib.sha1(password.encode('utf-8')).hexdigest()
                if newhash == hash:
                    return password
                elif newhash.upper() == hash:
                    return password
                elif newhash.lower() == hash:
                    return password
            if(hashmethod == 'sha256'):
                newhash = hashlib.sha256(password.encode('utf-8')).hexdigest()
                if newhash == hash:
                    return password
                elif newhash.upper() == hash:
                    return password
                elif newhash.lower() == hash:
                    return password
            if(hashmethod == 'sha384'):
                newhash = hashlib.sha384(password.encode('utf-8')).hexdigest()
                if newhash == hash:
                    return password
                elif newhash.upper() == hash:
                    return password
                elif newhash.lower() == hash:
                    return password
            if(hashmethod == 'sha512'):
                newhash = hashlib.sha512(password.encode('utf-8')).hexdigest()
                if newhash == hash:
                    return password
                elif newhash.upper() == hash:
                    return password
                elif newhash.lower() == hash:
                    return password
            