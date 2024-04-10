'''import statements required to execute code given below'''
import argparse
import socket
import json
from Crypto.Hash import HMAC,SHA256
import secrets
import select
import sys
from Crypto.Random.random import getrandbits
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import base64
from datetime import timezone
import datetime


'''class with the functionalities required to etablish a secured communication with client'''
class ChatApp_Server:
    def __init__(self):
        '''using arg parser command line to get the input data of port and file_name'''
        self.parser = argparse.ArgumentParser(
                        prog = 'Chat Application',
                        description = 'Securely exchange message between users')
        self.parser.add_argument('port',type=int,help='port number to establish incoming connection on the machine')
        self.parser.add_argument('file_name',help='file name with directory of user details')
        self.args=self.parser.parse_args()
        '''declaring variable to use in the function'''
        self.host_add=socket.gethostname()
        self.port_no=self.args.port
        self.file_name=self.args.file_name
       
        self.falg='False'
        self.dest_port_no=0
        self.dest_host_add=''
        self.dest_password=''
        
    '''function to establish the connection to send and receive data'''
    def connection_establishment(self):
            '''creating a socket'''
            print("----------------Welcome to the Chat App - Server!!!-------------------\n")
            self.server_con=socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
            print("Host address: ", self.host_add)
            print("Port Number: ",self.port_no)
            '''binding the host add and port number to accept a connection'''
           
            self.server_con.bind((self.host_add, self.port_no))
            
            '''listening for an incoming connection'''
            self.server_con.listen(1)
           
            print('\n')
            print('-----------------------------------------------------')
            print("server is listening...")
            print('-----------------------------------------------------')
            print('\n')
            while True: 
                '''using select statement to check for a incoming connection message and user input'''
                readable, writable, exceptional = select.select([self.server_con,sys.stdin], [], [],35)
                
                if(readable is None):
                    print("timeout")
                for data in readable:

                    '''when there is an incoming message accepting the connection '''
                    if data == self.server_con :
                        
                        server_c=bytes('server wants to receive','utf-8')
                        '''accepting the connection'''
                       
                        self.connection, self.address = self.server_con.accept()
                        
                        '''calling the chap function to perform mutual authentication'''
                        
                        ret_val=self.chap_challenge()
                        if(ret_val):
                           
                            print('\n\n')
                          
                            print('-----------------------------------------------------')
                            print("mutual athentication is successful and connection established to securely exchange messages")
                            print('-----------------------------------------------------')
                            print('\n\n')
                            self.connection.send(server_c)
                            '''calling the function to display the chap message'''
                            print('\n\n')
                          
                            print('-----------------------------------------------------')
                            print("server is receiving messages")
                            print('-----------------------------------------------------')
                            print('\n\n')
                            self.pdu_display()
                        else:
                            
                            print("Mutual authentication failed and connection failed")
                            print('\n\n')
                        print('-----------------------------------------------------')
                        print(" Closing the client connection")
                        print('-----------------------------------------------------')
                        self.connection.close()
                    '''using stdin '''
                    if data==sys.stdin:
                       
                        message_c=bytes('server wants to send','utf-8')
                        print('-----------------------------------------------------')
                        print('server is sending the message')
                        print('-----------------------------------------------------')
                        self.input_value()
                        '''checking each records to fetch the given username and password'''
                        flag=False
                        for record in self.file_value:
                            if(self.user_input_username == record['username']):
                                flag=True
                                '''checking if the details given by users and the directory matches if not closing the connection'''
                                if(record['port']==self.dest_port_no and record['ip']==self.dest_host_add and record['password']==self.dest_password):
                                    '''accepting the incoming connection'''
                                  
                                  
                                    self.connection, self.address = self.server_con.accept()
                                    print('\n')
                                    print('-----------------------------------------------------')
                                    print(f'Establishing a connection with {self.user_input_username}')
                                    print('-----------------------------------------------------')
                                    print('\n')
                                    '''calling chap function to perform mutua authentication'''
                                   
                                    ret_val=self.chap_challenge()
                               
                                    if(ret_val):
                                        print('\n\n')
                                        print('-----------------------------------------------------')
                                       
                                        print("mutual athentication is successful and connection established securely")
                                        print('-----------------------------------------------------')
                                        print('\n\n')
                                        self.connection.send(message_c)
                                        '''function to display to generate the pdu format of message to send the user'''
                                      
                                        pdu_val=self.pdu_msg()
                                        '''serializing the output to send to the client'''

                                        pdu_value=json.dumps(pdu_val).encode('utf-8')
                                        
                                        self.connection.send(pdu_value)
                                        '''receiving input from the client'''
                                        data = self.connection.recv(1024).decode()
                                        if(data): 
                                            '''validating if ack or nack message has been received'''
                                            val=self.ack_nack_msg(data)
                                            if not(val):
                                                '''closing the connection when receiving a nack'''
                                                self.close_connection()
                                            break
                                        
                                    else:
                                        print('\n\n')
                                        print('-----------------------------------------------------')
                                        print("Mutual authentication failed and connection failed")
                                        print('-----------------------------------------------------')
                                        print('\n\n')
                                        '''closing the connection when mutual authentication fails'''
                                        self.close_connection()
                                else:
                                    print('\n\n')
                                    print('-----------------------------------------------------')
                                    print("Given input does not match with the user")
                                    print('-----------------------------------------------------')
                                    print('\n\n')
                        if not (flag):
                                print('-----------------------------------------------------')
                                print("Given username is not available in contact list")
                                print('-----------------------------------------------------')
                                self.connection.close()
                        '''after sending message to the client closing the client connection'''
                        print('-----------------------------------------------------')
                        print("Sent message to the client and closing the client connection ")
                        print('-----------------------------------------------------')
                        self.connection.close()
                        
    '''function to encrypt the message to be sent to the client using encryption key generated from key generation function'''                
    def AES_CBC_encrypt(self,input_message):
      
        input_msg=input_message.encode('utf-8')
        '''using iv 16 byte by slicing it [0:16] to encrypt the message'''
        cipher = AES.new(self.encryption_key_bytes, AES.MODE_CBC,self.cbc_initial_vec_bytes[:16])
        msg =cipher.encrypt(pad(input_msg,AES.block_size))
        encrypt=msg.hex()
        return encrypt
    '''function to send the message in a pdu format'''
    def pdu_msg(self):
       
        input_message=input("Enter the message to send: ")
        '''calling the encryption function to encrypt the message'''
        encrypt_body = self.AES_CBC_encrypt(input_message)
        '''base64 encoding AESCBC encoded message '''
        text_bytes = encrypt_body.encode("ascii") 
        text_base64_bytes = base64.b64encode(text_bytes)
        text_base64_string = text_base64_bytes.decode("ascii")
        '''calling the function log to ge the time stamp'''
        time_stamp_val=self.log()
        pdu_value = {'header': {'msg_type' : 'text','timestamp':time_stamp_val},
            'body': text_base64_string,
            'security':{'hmac': {'type':'SHA256'},
            'encryption':'AESECB256'}}
        '''serializing the function to send the client'''
        pdu_val_bytes=json.dumps(pdu_value).encode('utf-8')
        '''calling the hmac crc function to calculate hmac and crc values of the pdu message'''
        hmac_ret,crc_ret=self.hmac_crc(pdu_val_bytes)
        '''replacing the hmac and crc values'''
        pdu_value = {'header': {'msg_type' : 'text','crc':crc_ret,'timestamp':time_stamp_val},
            'body': text_base64_string,
            'security':{'hmac': {'type':'SHA256','hash':hmac_ret},'encryption':'AESECB256'}}
       
        return pdu_value
    '''function to display the message which the client as sent'''
    def pdu_display(self):
       
        while self.connection:
            '''receiving the message'''
            pdu_data = self.connection.recv(1024).decode()
            if pdu_data:
                '''desearlizing the message'''
                serial_input=json.loads(pdu_data)
                '''validating the message in the pdu format for confidentiality and integrity'''
                self.pdu_validation(serial_input)
                '''base64 decoding the message'''
                pdu_string_bytes = base64.b64decode(serial_input['body'])
                pdu_string = pdu_string_bytes.decode("ascii") 
                '''using AES CBC decrypt to decrypt the message'''
                ret_decrypt_val=self.AES_CBC_decrypt(pdu_string)
                ret_decrypt=ret_decrypt_val.decode()

                print('-----------------------------------------------------')
                print("Message: " , (ret_decrypt)) 
                print('-----------------------------------------------------')
                print('\n\n')
                break 
            else:
                break
    '''function to calculate the hmac and crc values'''
    def hmac_crc(self,pdu_val_bytes):
       
        hmac_val= HMAC.new(self.hmac_key_bytes,pdu_val_bytes,digestmod=SHA256).hexdigest()
        crc_val=hex(zlib.crc32(pdu_val_bytes) & 0xffffffff)
        return hmac_val,crc_val
    '''function to generate the ack and nack message'''
    def ack_nack_msg(self,val):
        
        ack_string=json.loads(val)
        val=self.message_validation(ack_string)
        if(val):
            ack_string=ack_string['header']['msg_type']
            if(ack_string == 'ack'):
                return True
            else:
                return False
        else:
            print('\n\n')
            print('-----------------------------------------------------')
            print('Ack/Nack message has been tampered')
            print('-----------------------------------------------------')
            print('\n\n')
            return False
    '''validating the message format in pdu format by comapring the crc and hmac value'''
    def pdu_validation(self,input_val):
      
        input_crc=input_val['header']['crc']
        input_hmac=input_val['security']['hmac']['hash']
        del input_val['header']['crc']
        del input_val['security']['hmac']['hash']
        input_val_f=json.dumps(input_val).encode('utf-8')
        '''calculating the crc value'''
        crc_val=hex(zlib.crc32(input_val_f) & 0xffffffff)
        '''calculating the hmac value'''
        try: 
           hmac_val= HMAC.new(self.hmac_key_bytes,input_val_f,digestmod=SHA256)
           '''verifying the hmac '''
           hmac_val.hexverify(input_hmac)
        except Exception as e:
            print("Exception occured",e)
        if(input_val['header']['msg_type']!= 'ack' or input_val['header']['msg_type']!='nack'):
            if(input_crc==crc_val ):
                self.msg_generation('ack',None)
            else:
                self.msg_generation('nack', None)
    '''function to validate the chap message received from client'''
    def message_validation(self,input_val):
        
        input_crc=input_val['header']['crc']
        input_hmac=input_val['security']['hmac']['hash']
        del input_val['header']['crc']
        del input_val['security']['hmac']['hash']
        input_val_d=json.dumps(input_val).encode('utf-8')
        '''calculating the crc value'''
        crc_val=hex(zlib.crc32(input_val_d) & 0xffffffff)
        '''calculating the hmac value'''
        hmac_val= HMAC.new(self.hmac_key_bytes,input_val_d,digestmod=SHA256)
        '''verifying the hmac value'''
        hmac_val.hexverify(input_hmac)
        if(input_crc==crc_val ):
            return True
        else:
           return False
    '''function to decrypt the encrypted message sent by client'''
    def AES_CBC_decrypt(self,decrypt_val):
    
        decrypt_val=bytes.fromhex(decrypt_val)
        '''using the iv value generated from the key generation steps by slicing [:16]'''
        decipher = AES.new(self.encryption_key_bytes, AES.MODE_CBC,self.cbc_initial_vec_bytes[:16])
        '''decrypting the message'''
        self.comment_log(decrypt_val)
        plain_text=unpad(decipher.decrypt(decrypt_val),AES.block_size)

        return plain_text
    
    '''function to perform the chap mutual authentication'''
    def chap_challenge(self):
       
        while True:
            '''receiving the message'''
            challenge_data = self.connection.recv(1024)
            if challenge_data:
                serial_input=json.loads(challenge_data)
                '''validating the incoming packet'''
                if('hello' not in serial_input['header']['msg_type']):
                    val=self.message_validation(serial_input)
                    if not (val):
                        print('\n\n')
                        print('-----------------------------------------------------')
                        print('The chap message received are tampered. Closing the connection')
                        print('-----------------------------------------------------')
                        print('\n\n')
                msg_data=serial_input['header']['msg_type']
                '''fetching the password for the username entered by the user'''
                if ('hello' in msg_data ):
                    username=msg_data[6:]
                    print("Username : ",username)
                    '''iterating through the directory to get the password'''
                    for record in self.file_value:
                        if(username==record['username']) :
                           self.password_val=record['password']
                           '''function to log the comments'''
                           
                           '''calling the function to perform key generation'''
                           shared_secret=self.key_generation(self.password_val)
                           rand_bit=secrets.randbits(256)
                           '''generating challenge message to send 256 random bits'''
                           self.msg_generation('challenge',rand_bit)
                           self.flag='True'
                    '''if username given by the user is not in the directory then the connection is closed'''
                    if not(self.flag):
                        print('-----------------------------------------------------')
                        print('The user provided does not exits in files')
                        print('-----------------------------------------------------')
                        self.close_connection()
                        break
                elif(serial_input['header']['msg_type']=='response'):
                    val=(str(self.key_der)+str(rand_bit)).encode()
                    '''calling the chap validation function to verify the response (password+challenge) message from client'''
                    val=self.chap_validation(serial_input['body'],val)
                    if(val):
                        '''generating the ack message'''
                        self.msg_generation('ack',None)
                    else:
                        '''generating the nack message'''
                        self.msg_generation('nack',None)
                        self.close_connection()
                        break
                elif(serial_input['header']['msg_type']=='challenge'):
                    str_to_bytes= (shared_secret+str(serial_input['body'])).encode()
                    hash_value = SHA256.new()
                    hash_value.update(str_to_bytes)
                    hash_output= hash_value.hexdigest()
                    '''generating the response messgae to send the client after receiving challenge message'''
                    self.msg_generation('response',hash_output)
                elif(serial_input['header']['msg_type']=='ack'):
                    return True
                elif(serial_input['header']['msg_type']=='nack'):
                    break
            else:
                break
    '''function to perform chap validation by comparing the find SHA256 of (password+256 random bit) generated'''
    def chap_validation(self,response,rand_val):
        
        hash_value = SHA256.new()
        hash_value.update(rand_val)
        hash_output= hash_value.hexdigest()
        '''comparing response from client with hash value server calculated'''
        if(response==hash_output):
            return True
        else:
            return False
    '''function to generate message structure which includes claculating crc,hmac and encryption value '''
    def msg_generation(self,msg_type,body_val):
       
        time_stamp_val=self.log()
        if(msg_type=='ack' or msg_type=='nack'):
            body_val=None
            encryption_val=None
        else:
            body_val=body_val
            encryption_val='AESCBC256'
        msg_gen={'header':{'msg_type' : msg_type,'timestamp':time_stamp_val}, 'body': body_val,
        'security':{'hmac': {'type':'SHA256'},'encryption':encryption_val}}
        '''serializing the message to calculate crc and hmac values'''
        msg_input=json.dumps(msg_gen).encode('utf-8')
        hmac_ret,crc_ret=self.hmac_crc(msg_input)
        msg_gen_f = {'header': {'msg_type' : msg_type,'crc':crc_ret,'timestamp':time_stamp_val},
            'body': body_val,
            'security':{'hmac': {'type':'SHA256','hash':hmac_ret},'encryption': encryption_val}}

        server_input=json.dumps(msg_gen_f).encode('utf-8')
        
        self.connection.send(server_input) 
        
       
    '''function to perform diffie hellman to derive the shared key which is used in key generation'''
    def diffie_hellman(self):
      
        prime  = 23
        base   = 5
        secret = {
                "priv_key" :      0,
                "pub_key" :       0,
                "server_pub_key" : 0,
                "shared_secret" : 0
                }
        priv_key = getrandbits( 16 )
        secret[ 'priv_key' ] = priv_key
        secret[ 'pub_key'  ] = ( base ** priv_key ) % prime
        '''exchanging the public key of server with client to dervie shared key'''
        pub_bytes_key= str(secret['pub_key']).encode()
        self.connection.send(pub_bytes_key)
        client_pub_key = self.connection.recv(1024).decode()
            
        secret[ 'server_pub_key' ] = int(client_pub_key)
        secret[ 'shared_secret' ] = ( secret[ 'server_pub_key' ] ** secret[ 'priv_key' ] ) % prime
        return secret[ 'shared_secret' ]
    
    '''function to calculate the key derivate of the password with shared key from diffie hellman'''
    def key_derivative(self,password,dhsk_secret_bytes):
        derived_key=HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=password
        ).derive(dhsk_secret_bytes)
        return derived_key
    '''funciion to generate keys required for the entire communication to happen using key derivative 
    function and diffie hellman shared key. '''
    def key_generation(self,password):
        
        bytes_pass=bytes(password,'utf-8')
        '''calling the diffie hellman function to get shared secret between client and server'''
        dhsk_secret=self.diffie_hellman()
       
        self.dhsk_secret_bytes=bytes(dhsk_secret)
        '''calling key derivative function to obtain the key for password'''
        self.key_der=self.key_derivative(bytes_pass,self.dhsk_secret_bytes)
        
        encryption_key= HMAC.new(self.key_der,self.dhsk_secret_bytes,digestmod=SHA256).hexdigest()
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
       

    '''function to load the user directory'''  
    def load_user_directory(self):
        self._file_name=open(self.file_name,"r")
        file_value=self._file_name.read()
        self.file_value=json.loads(file_value)

        
    '''function to get the user input when the server wants to send the message
    giving 2 choices to the user either load from directory or getting input from user'''

    def input_value(self):
        message_send=input("Enter the message to be sent: ")
        choice=int(input("Enter the option to establish the connection \n 1 To load from directory \n 2 To provide the details\n"))
        if(choice==1):
            print('-----------------------------------------------------')
            self.user_input_username=input("Enter the username to send message with: ")
            print('-----------------------------------------------------')
            for user in self.file_value:
                if(self.user_input_username==user['username']):
                    self.dest_port_no=user['port']
                    self.dest_host_add=user['ip']
                    self.dest_password=user['password']
        elif(choice==2):
            print('-----------------------------------------------------')
            print("Enter the following details required to establish a connection to the destination")
            print('-----------------------------------------------------')
            self.user_input_username=input("Enter the username to send message with: ")
            self.dest_port_no= input("Enter destination port number")
            self.dest_host_add=input("Enter destination host address")
            self.dest_password=input("Enter the destination password")
    '''function to log the comments'''
    def comment_log(self,msg): 
        file_name=open('log_server','w+')
        date_time = datetime.datetime.now(timezone.utc)
        utc_time = date_time.replace(tzinfo=timezone.utc)
        utc_timestamp = str(utc_time.timestamp())
        log_msg=(utc_timestamp+'::'+str(msg))
        file_name.write(log_msg +'\n')
        file_name.close()

    '''function to calculate utc timestamp value'''
    def log(self):
        utc_time = datetime.datetime.now(timezone.utc)
        utc = utc_time.replace(tzinfo=timezone.utc)
        timestamp = str(utc.timestamp())
        return timestamp
    '''function to close the connection''' 
    def close_connection(self):
        print('\n\n')
        print('-----------------------------------------------------')
        print('closing the connection')
        print('-----------------------------------------------------')
        print('\n\n')
        self.server_con.close() 
   

if __name__ == '__main__':
    '''main function to create the objects and to call the function'''
    try:
        hatapp_server_obj=ChatApp_Server()
        hatapp_server_obj.load_user_directory()
        hatapp_server_obj.connection_establishment()
    
    except socket.timeout:
        print("Exception occurred due to timout")
        sys.exit(1)
    except KeyboardInterrupt:
        print("The connection interrupted by keyboard input")
        sys.exit(1)
    except socket.error:
        print("Exception occurred while creating and using the socket")
        sys.exit(1)
    except:
        print("An exception occured")
        sys.exit(1)
   
   
   
   