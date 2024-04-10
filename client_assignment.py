'''import statements required to execute code given below'''
from Crypto.Hash import HMAC,SHA256
import socket
import argparse
import json
import sys
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Random.random import getrandbits
import select
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad,pad
from datetime import timezone
import datetime
import base64
'''class with the functionalities required to etablish a secured communication with server'''
class ChatApp_Client():
    def __init__(self):
        '''using arg parser command line to get the input data of port and file_name'''

        self.parser = argparse.ArgumentParser(
                        prog = 'Client program',
                        description = 'Opens a TCP socket to listen on from one connection and closes when receiving a close message ')
        self.parser.add_argument('host',help='The first value is host address to establish server connection')
        self.parser.add_argument('port',type=int,help='The second value is port number to establish server connection')
        self.parser.add_argument('password',help='The third value is the password to establish chap')
        self.args=self.parser.parse_args()
        '''declaring variable to use in the function'''
        self.host_add=self.args.host
        self.port_no=self.args.port
        self.passwd=self.args.password
        self.msg_count=0
        self.nack_count=0
     
        self.connection_establishment()
    '''function to establish the connection to send and receive data'''
    def connection_establishment(self):
        
        while True:
            '''using select statement to check for a incoming connection message and user input'''
           
            print("----------------Welcome to the Chat App - Client!!!-------------------\n")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.client_con:
                readable, writable, exceptional = select.select([self.client_con], [], [],35)
                if(readable is None ):
                    print('Timeout')
                '''connecting with the incoming connection of the server'''
                self.client_con.connect((self.host_add, self.port_no))
                
                '''calling the function to perform mutual chap authentication'''
                
                ret_val=self.chap_challenge()
                if(ret_val):
                    print('\n\n')
                    print('-----------------------------------------------------')
                    print("mutual athentication is successful and connection established securely")
                    print('-----------------------------------------------------')
                    print('\n\n')
                   
                    '''after mutual authentication is performed, the server receives message from server whether 
                    it wants to send a message or receive a message'''
                    recv_server_message=self.client_con.recv(1024).decode()
                    if('receive'in recv_server_message ):
                            print('\n\n')
                          
                            print('-----------------------------------------------------')
                            print('Client is sending message')
                            print('-----------------------------------------------------')
                            print('\n\n')
                            '''calling function to generate the message pdu format '''
                            
                            pdu_val=self.pdu_msg()
                           
                            '''serializing the data before sending it to the client'''
                            pdu_value=json.dumps(pdu_val).encode('utf-8')
                            self.client_con.send(pdu_value)
                            '''receiving the data from server'''
                            data = self.client_con.recv(1024).decode()
                            if(data): 
                                '''calling function to send ack or nack message '''
                                self.ack_nack_msg(data)
                                
                                break
                               
                    if('send' in recv_server_message):  
                        '''calling the function to display the chap message'''   
                        print('\n\n')
                      
                        print('-----------------------------------------------------')
                        print('Client is receiving the message')    
                        print('-----------------------------------------------------')
                        print('\n\n')          
                        self.pdu_display()
                       
                        break
                else:
                    '''when mutual authentication fails, socket connection is closed'''
                    print('\n\n')
                   
                    print('-----------------------------------------------------')
                    print("Mutual authentication failed and connection failed")
                    print('-----------------------------------------------------')
                    print('\n\n')
                   
                    self.close_connection()
                    break
                
    '''function to perform chap mutual authentication'''
    def chap_challenge(self):
        user_name=input('Please enter your username to send message: ')
        '''generating the hello message'''
        hello_pack= ('hello '+user_name)
        msg_gen={'header':{'msg_type' :hello_pack, 'body': None}}
        msg_gen_bytes=json.dumps(msg_gen).encode('utf-8')
        self.client_con.send(msg_gen_bytes) 
        '''function to generate the key generation'''
        shared_sec=self.key_generation()
       
        while True:
            challenge_data = (self.client_con.recv(1024)).decode('utf-8')
          
            if(challenge_data):
                serial_input=json.loads(challenge_data)
                '''function to validate the message'''
                serial_val=self.message_validation(serial_input)
                if(serial_val):
                    '''function to check the check the input message based on message type'''
                    if(serial_input['header']['msg_type']== 'challenge'):
                        '''concatinating the password and random variable of challenge message'''
                        str_to_bytes= (str(self.key_der)+str(serial_input['body'])).encode()
                        hash_value = SHA256.new()
                        hash_value.update(str_to_bytes)
                        hash_output= hash_value.hexdigest()
                        '''function to generate the response message pdu'''
                        self.msg_generation('response',hash_output)
                    elif(serial_input['header']['msg_type']=='ack'):
                        '''generating the 256 random bytes'''
                        rand_bit=secrets.randbits(256)
                        '''generating the challenge message'''
                        self.msg_generation('challenge',rand_bit)
                    elif(serial_input['header']['msg_type']=='nack'):
                        break
                    elif(serial_input['header']['msg_type']=='response'):
                        '''concatinating the chap secret of key generation and rand bits of challenge message to 
                        validate the connection '''
                        val=(shared_sec+str(rand_bit)).encode()
                        '''validating the response received from client to do mutual authentication'''
                        val=self.chap_validation(serial_input['body'],val)
                        '''sending an ack or nack based on the validation of response message from server'''
                        if(val):
                            self.msg_generation('ack',None)
                        
                            return True
                        else:
                            self.msg_generation('nack',None)
                            print('\n\n')
                            print('-----------------------------------------------------')
                            print("authentication failed as the chap data has been tampered")
                            print('-----------------------------------------------------')
                            print('\n\n')
                            '''chap validation failed and so closing the connection'''
                          
                            self.close_connection()
                           
                else:
                    print('\n\n')
                    print('-----------------------------------------------------')
                    print("authentication failed as the chap data received has been tampered")
                    print('-----------------------------------------------------')
                    print('\n\n')
                    
                    self.close_connection()
                
            else:
                break
    '''function to validate the message received from server using crc and hmac calculations'''
    def message_validation(self,input_val):
        input_crc=input_val['header']['crc']
        input_hmac=input_val['security']['hmac']['hash']
       
        del input_val['header']['crc']
        del input_val['security']['hmac']['hash']
        input_val=json.dumps(input_val).encode('utf-8')
        '''calculating the crc value of message received'''
        crc_val=hex(zlib.crc32(input_val) & 0xffffffff)
        '''calculating the hmac value'''
        try:
           hmac_val= HMAC.new(self.hmac_key_bytes,input_val,digestmod=SHA256)
           '''verifying the hmac value calculated with the hmac value in the pdu message sent by server'''
           hmac_val.hexverify(input_hmac)
        except Exception as e:
            print("Exception occured",e)
        if(input_crc==crc_val ):
            return True
        else:
           return False
    '''function to display the message in pdu format received from the client'''
    def pdu_display(self):
       
        while self.client_con:
            pdu_data = self.client_con.recv(1024).decode()
           
            if pdu_data:
                serial_input=json.loads(pdu_data)
                '''validating the message in pdu format received from server'''
                self.pdu_validation(serial_input)
                '''decoding the base 64 encoded message'''
                pdu_string_bytes = base64.b64decode(serial_input['body'])
                pdu_string = pdu_string_bytes.decode("ascii") 
                '''decrypting the message with AES CBC encryption using initialization vector (iv) which 
                is generated from key generation function which is of 32 bytes soo sliced it to [0:16]'''
                ret_decrypt_val=self.AES_CBC_decrypt(pdu_string)
                ret_val=ret_decrypt_val.decode()
                print('-----------------------------------------------------')
                print("The message received from server: " , ret_val) 
                
                print('-----------------------------------------------------')
                self.client_con.close()
                break 
            else:
                break
    '''function to generate message in pdu format to send the server'''
    def pdu_msg(self):
        print('\n\n')
        print('-----------------------------------------------------')
        input_message=input("Enter the message to send: ")
        print('-----------------------------------------------------')
        print('\n\n')
        '''calling the AES CBC encrypt function to encrypt the message sent to the server using 
        initialization vector (iv) which is 32 bytes so slicing it to get 16 bytes[0:16]'''
        encrypt_body = self.AES_CBC_encrypt(input_message)
        '''encoding the message using base64 encryption''' 
        text_bytes = encrypt_body.encode("ascii") 
        text_base64_bytes = base64.b64encode(text_bytes)
        text_base64_string = text_base64_bytes.decode("ascii")
        time_stamp_val=self.log()
        '''pdu message format'''
        pdu_value = {'header': {'msg_type' : 'text','timestamp':time_stamp_val},
            'body': text_base64_string,
            'security':{'hmac': {'type':'SHA256'},
            'encryption':'AESECB256'}}
        pdu_val_bytes=json.dumps(pdu_value).encode('utf-8')
        '''calling the hmac function to generate the crc and hmac values for the message to be sent to the server'''
        hmac_ret,crc_ret=self.hmac_crc(pdu_val_bytes)
        pdu_value = {'header': {'msg_type' : 'text','crc':crc_ret,'timestamp':time_stamp_val},
            'body': text_base64_string,
            'security':{'hmac': {'type':'SHA256','hash':hmac_ret},'encryption':'AESECB256'}}
        
        return pdu_value
    '''function to log the timestamp in utc format'''
    def log(self):
        time = datetime.datetime.now(timezone.utc)
        utc = time.replace(tzinfo=timezone.utc)
        timestamp = str(utc.timestamp())
        return timestamp
    '''function to calculate the hmac and crc values'''
    def hmac_crc(self,pdu_val):
        hmac_val= HMAC.new(self.hmac_key_bytes,pdu_val,digestmod=SHA256).hexdigest()
        crc_val=hex(zlib.crc32(pdu_val) & 0xffffffff)
        
        return hmac_val,crc_val
    '''function to encrypt the body of the message using encryption key and iv generated from key generation process'''
    def AES_CBC_encrypt(self,input_message):
        input_msg=input_message.encode('utf-8')
        cipher = AES.new(self.encryption_key_bytes, AES.MODE_CBC,self.cbc_initial_vec_bytes[:16])
        '''padding the encryption to avoid key and value error'''
        msg =cipher.encrypt(pad(input_msg,AES.block_size))
        encrypt=msg.hex()
      
        return encrypt
    '''function to generate ack and nack messages based on pdu validation'''
    def ack_nack_msg(self,val):
        ack_string=json.loads(val)
        '''validating the message received from server which is in pdu format'''
        self.pdu_validation(ack_string)
        ack_string=ack_string['header']['msg_type']
        '''based on the validation sending ack or nack'''
        if(ack_string == 'ack'):
            self.close_connection()
        else:
            self.close_connection()
    '''function to validate the pdu message received from server by calculate the crc and hmac values'''
    def pdu_validation(self,input_val):
        input_crc=input_val['header']['crc']
        input_hmac=input_val['security']['hmac']['hash']
     
        del input_val['header']['crc']
        del input_val['security']['hmac']['hash']
        '''serializing the message to calculate the crc and hmac'''
        input_val_d=json.dumps(input_val).encode('utf-8')
        '''calculating the crc value using zlib library'''
        crc_val=hex(zlib.crc32(input_val_d) & 0xffffffff)
        '''calculating the hmac value'''
        try:
          hmac_val= HMAC.new(self.hmac_key_bytes,input_val_d,digestmod=SHA256)
          '''verifying the hmac value calculated using hex verify'''
          hmac_val.hexverify(input_hmac)
        except Exception as e:
            print('Exception occurred',e )
        if(input_val['header']['msg_type']!= 'ack' or input_val['header']['msg_type']!='nack'):
            '''if both crc and hmac are verified we send an ack message else sending a nack message'''
            if(input_crc==crc_val ):
                self.msg_generation('ack',None)
            else:
                self.msg_generation('nack', None)
        else:
            if(input_crc==crc_val ):
                return True
            else:
                return False
            
    '''function to generate the message to send the server which has the header, bosy and the security part with encryption and 
    crc, hmac values'''                          
    def msg_generation(self,msg_type,body_val):
        time_stamp_val=self.log()
        if(msg_type=='ack' or msg_type== 'nack'):
            body_val=None
            encryption_val=None
        else:
            body_val=body_val
            encryption_val='AESCBC256'
        '''message pdu format '''
        msg_gen={'header':{'msg_type' : msg_type,'timestamp':time_stamp_val}, 'body': body_val,
        'security':{'hmac': {'type':'SHA256'},'encryption':encryption_val}}
        msg_input=json.dumps(msg_gen).encode('utf-8')
        '''calculating the hmac and crc values for the message and adding them in the pdu'''
        hmac_ret,crc_ret=self.hmac_crc(msg_input)
        msg_gen_f = {'header': {'msg_type' : msg_type,'crc':crc_ret,'timestamp':time_stamp_val},
            'body': body_val,
            'security':{'hmac': {'type':'SHA256','hash':hmac_ret},'encryption': encryption_val}}
        server_input=json.dumps(msg_gen_f).encode('utf-8')
        
        self.client_con.send(server_input) 

    '''function to validate the chap authentication to establish a secured connection'''
    def chap_validation(self,response,rand_val):
       
        hash_value = SHA256.new()
        hash_value.update(rand_val)
        hash_output= hash_value.hexdigest()
        '''comparing the SHA256 hash send by the server with the concated value of secret and challenge.
        if they match then the connection is secured and the conversation can be started'''
        if(response==hash_output):
            return True
        else:
            return False
    '''function to decrypting the message body received from server'''
    def AES_CBC_decrypt(self,decrypt_val):
       
        decrypt_val=bytes.fromhex(decrypt_val)
        '''decrypting using the encryption key and initialization vector (iv) from key generation process'''
        decipher = AES.new(self.encryption_key_bytes, AES.MODE_CBC,self.cbc_initial_vec_bytes[:16])
        plain_text=unpad(decipher.decrypt(decrypt_val),AES.block_size)
        self.comment_log(decipher)
        return plain_text
    '''function to log'''
    def comment_log(self,msg): 
        file_name=open('log_client','w+')
        date_time = datetime.datetime.now(timezone.utc)
        utc_time = date_time.replace(tzinfo=timezone.utc)
        utc_timestamp = str(utc_time.timestamp())
        log_msg=(utc_timestamp+'::'+str(msg))
        file_name.write(log_msg +'\n')
        file_name.close()

    '''function to perform diffie hellman to derive the shared key which is used in key generation'''
    def diffie_hellman(self):
        prime  = 23
        base   = 5
        secret = {
                "priv_key" :      0,
                "pub_key" :       0,
                "client_pub_key" : 0,
                "shared_secret" : 0
                }
        priv_key = getrandbits( 16 )

        secret[ 'priv_key' ] = priv_key
        secret[ 'pub_key'  ] = ( base ** priv_key ) % prime
        '''exchanging the public key of server with client to dervie shared key'''
        pub_bytes_key= str(secret['pub_key']).encode()
        client_pub_key = self.client_con.recv(1024).decode()
        self.client_con.send(pub_bytes_key)
       
        secret[ 'client_pub_key' ] = int(client_pub_key)
        secret[ 'shared_secret' ] = (  secret[ 'client_pub_key' ] ** secret[ 'priv_key' ] ) % prime
        return secret[ 'shared_secret' ]
    
    '''function to calculate the key derivate of the password with shared key from diffie hellman'''
    def key_derivative(self,password,shared_key):
        derived_key=HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=password
        ).derive(shared_key)
        return derived_key
    '''funciion to generate keys required for the entire communication to happen using key derivative 
    function and diffie hellman shared key. '''
    def key_generation(self):
        bytes_pass=bytes(self.passwd,'utf-8')
        '''calling the diffie hellman function to get shared secret between client and server'''
        dhsk_secret=self.diffie_hellman()
        
        dhsk_secret_bytes=bytes(dhsk_secret)
        '''calling key derivative function to obtain the key for password'''
        self.key_der=self.key_derivative(bytes_pass,dhsk_secret_bytes)
     
        encryption_key= HMAC.new(self.key_der,dhsk_secret_bytes,digestmod=SHA256).hexdigest()
        '''performning HMAC SHA256 to generate encryption key which is used to encrypt and decrypt messages'''
        self.encryption_key_bytes=bytes.fromhex(encryption_key)
        '''performing SHA256 on the encryption key to get the iv(initialization vector) required for performing encryption and decryption on messages'''
        hash_value_iv = SHA256.new()
        hash_value_iv.update(self.encryption_key_bytes)
        cbc_intial_vec= hash_value_iv.hexdigest()

        self.cbc_initial_vec_bytes=bytes.fromhex(cbc_intial_vec)
      
        '''performing SHA256 on the iv (initialization vector) to get hmac key to perform hmac'''
        hash_value_hmac = SHA256.new()
        hash_value_hmac.update(self.cbc_initial_vec_bytes)
        hmac_key= hash_value_hmac.hexdigest()
     
        self.hmac_key_bytes=bytes.fromhex(hmac_key)
        '''performing SHA256 on the hmac key to get the chap secret which is used in the mutual chap authentication '''
        hash_value_chap = SHA256.new()
        hash_value_chap.update(self.hmac_key_bytes)
        self.chap_secret= hash_value_chap.hexdigest()
        return self.chap_secret
    '''function to close the connection'''
    def close_connection(self):
        print('-----------------------------------------------------')
        print('closing the connection')
        print('-----------------------------------------------------')
        self.client_con.close()   
        exit(1)


   

if __name__ == '__main__':
    '''obj created to call the chatapp client'''
    #try and catch blocks to handle the exceptions
   
    try:
        client_obj=ChatApp_Client()
    except socket.timeout:
        print("Exception occurred due to timout")
        sys.exit(1)
    except KeyboardInterrupt:
        print("The connection interrupted by keyboard input")
        sys.exit(1)
    except socket.error:
        print("Exception occurred while creating and using the socket")
        sys.exit(1)
    
   