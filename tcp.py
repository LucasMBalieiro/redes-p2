import asyncio
import math
from tcputils import *


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no)
            ack_no = seq_no + 1
            header = fix_checksum(make_header(dst_port, src_port, seq_no, ack_no, FLAGS_SYN + FLAGS_ACK), src_addr, dst_addr)
            self.rede.enviar(header, src_addr)
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.seq_no = seq_no
        self.next_seq_no = seq_no + 1
        self.ack_no = seq_no + 1
        self.callback = None
        self.timer = None
        self.timer_rodando = False
        self.not_yet_acked = b''


    def handle_timeout(self):
        self.timer.cancel()
        self.timer_rodando = False
        
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        header = fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK), dst_addr, src_addr)

        payload = self.not_yet_acked[:MSS]

        self.servidor.rede.enviar(header + payload, src_addr)
        self.timer = asyncio.get_event_loop().call_later(0.5, self.handle_timeout)
        self.timer_rodando = True


    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        
        print('recebido payload: %r' % payload)

        if (self.ack_no != seq_no ):
            return

        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.ack_no += 1
            header = fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK), dst_addr, src_addr)
            self.servidor.rede.enviar(header, src_addr)
            self.callback(self, b'')
            del self.servidor.conexoes[self.id_conexao]

        self.ack_no += len(payload)
        
        if (len(payload) > 0):
            header = fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK), dst_addr, src_addr)
            self.callback(self, payload)
            self.servidor.rede.enviar(header, src_addr)
            return
        
        if ((flags & FLAGS_ACK) == FLAGS_ACK):
            if self.timer_rodando:
                self.timer.cancel()
                self.timer = None
                self.timer_rodando = False

            self.not_yet_acked = self.not_yet_acked[ack_no - self.seq_no :]
            self.seq_no = ack_no
            
            if ack_no < self.next_seq_no:
                self.timer_rodando = True
                self.timer = asyncio.get_event_loop().call_later(0.5, self.handle_timeout)

            return



    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):

        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        for i in range(math.ceil(len(dados) / MSS)):
            header = make_header(dst_port, src_port, self.next_seq_no, self.ack_no, FLAGS_ACK)

            payload = dados[i * MSS : (i + 1) * MSS]
            segment = fix_checksum(header + payload,dst_addr, src_addr)
            self.servidor.rede.enviar(segment, src_addr)
            self.next_seq_no += len(payload)
            
            self.not_yet_acked += payload
            if not self.timer_rodando:
                self.timer_rodando = True
                self.timer = asyncio.get_event_loop().call_later(0.5, self.handle_timeout)


    def fechar(self):

        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        header = make_header(dst_port, src_port, self.next_seq_no, self.ack_no, FLAGS_FIN)
        segment = fix_checksum(header, dst_addr, src_addr)
        self.servidor.rede.enviar(segment, src_addr)

        pass