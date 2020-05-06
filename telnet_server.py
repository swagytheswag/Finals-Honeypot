import socket
import threading
import subprocess

class TelnetServer(object):
    def __init__(self):
        """
        initializing the telnet server object
        """
        self.HOST = '0.0.0.0'
        self.PORT = 44444
        self.BUFFSIZ = 1024
        self.ADDR = (self.HOST, self.PORT)

    def start(self):
        """
        starting the sever
        :return:
        """
        print 'Starting the server.'
        self.serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serversock.bind(self.ADDR)
        self.serversock.listen(4)

        self.lock = threading.Lock()
        self.clientsocks = [] #list of clients connected
        print 'Waiting for connections...'

    def mainloop(self):
        client_handler(self, self.serversock.accept()).start()


class client_handler(threading.Thread):
    """
    object for a client connected
    """
    def __init__(self, server, (socket,address)):
        threading.Thread.__init__(self)
        self.server = server
        self.client_socket = socket
        self.address = address

    def run(self):
        """
        handles connecting the client, commands, and disconnecting
        """
        # appends the client to the server's client list
        self.server.lock.acquire()
        self.server.clientsocks.append(self)
        self.server.lock.release()
        print '%s:%s connected.' % self.address
        # prompt help
        self.client_socket.send(self.handle_data('help'))
        # collect data until client disconnects:
        while True:
            self.client_socket.send('/>')
            data = self.recieve_data("")
            answer = self.handle_data(data.replace("\r\n", ""))
            if not answer: # if client disconnected
                break
            self.client_socket.send(answer)

        # disconnects the client
        self.client_socket.close()
        print '%s:%s disconnected.' % self.address
        self.server.lock.acquire()
        self.server.clientsocks.remove(self)
        self.server.lock.release()

    def recieve_data(self, data):
        """
        recieves data from the client recursively.
        the client sends data character-by-character.
        the function recieves the characters recursively, until "enter" has been pressed ("\r\n").
        it also makes sure to handle backspace.
        :param data - string:
        :return the full-length data received from user until the press of an 'enter':
        """
        try:
            recieved = self.client_socket.recv(self.server.BUFFSIZ) # received character
            if recieved == '\b':                                    # if received a backspace
                if data:                                                # if we have received something by now
                    data = data[:-1]                                        # delete the last character of the whole string by far
                    self.client_socket.send(' \b')                          # delete the prompted character from his screen
                else:                                                   # else, if he didn't send any character yet
                    self.client_socket.send('>')                            # prompt on his screen the deleted '>'
            else:                                                   # else, if it wasn't a backspace
                data += recieved                                        # add the received character to the whole string
            if not data.endswith("\r\n"):                           # if didn't press enter
                data = self.recieve_data(data)                          # call this function again with the collected string
            return data                                             # finally, if client pressed enter, return the collected string
        except:
            return 'quit\r\n'                                       # if client crashed, just quit

    def handle_data(self, data):
        """
        generates an answer based on the data given
        :param data: string given from the client
        :return answer: string to send back to the client
        """
        answer = ''
        if data == 'help':
            answer = 'This is a command execution server:\r\n'
            answer += '\thelp'.ljust(20, ' ')+'- display this prompt\r\n'
            answer += '\tquit'.ljust(20, ' ')+'- quit the session\r\n'
            answer += '\techo [string]'.ljust(20, ' ')+'- echo :)\r\n'
            answer += '\texecute [command]'.ljust(20, ' ')+'- executes the command\r\n'
        elif data == 'quit':
            answer = ''
        elif data.startswith('echo'):
            answer = data[4::] + "\r\n"
        elif data.startswith('execute'):
            try:
                answer = subprocess.check_output(data[7::], shell=True)
            except:
                answer = 'An error has occurred.\r\n'
        else:
            answer = 'Unknown command. Type "help" for the list of commands.\r\n'
        return answer


telnet_server = TelnetServer()
telnet_server.start()
while True: # wait for socket to connect
    telnet_server.mainloop()