#!/usr/bin/env python3
"""

The formats are:

type:4C4D - execute this command (with more coming)
type:4C4F - execute this command
type:594B - reply (with more coming)
type:594D - last reply

Each one is an 8 byte id (to link replies to command), followed by JSON.
"""
import logging
from pyln.client import Plugin, RpcError  # type: ignore
import json
import textwrap
import multiprocessing
from typing import Dict, Tuple, Optional

plugin = Plugin()

# Messages may be split across multiple CONTINUES, then TERM.
HAWALA_OFFER_CONTINUES = 0x573B
HAWALA_OFFER_TERM = 0x573D
HAWALA_TAKE = 0x575B
HAWALA_QUOTE = 0x575D


def send_msg(plugin, peer_id, msgtype, idnum, contents):
    """Messages are form [8-byte-id][data]"""
    msg = (msgtype.to_bytes(2, 'big')
           + idnum.to_bytes(8, 'big')
           + bytes(contents, encoding='utf8'))
    plugin.rpc.call(plugin.msgcmd, {'node_id': peer_id, 'msg': msg.hex()})


def send_msgs(plugin, peer_id, idnum, obj, msgtype_cont, msgtype_term):
    # We can only send 64k in a message, but there is 10 byte overhead
    # in the message header; 65000 is safe.
    parts = textwrap.wrap(json.dumps(obj), 65000)
    plugin.log(f"Sending message in {len(parts)} parts, id {idnum}, {msgtype_cont} - {msgtype_term}")
    for p in parts[:-1]:
        send_msg(plugin, peer_id, msgtype_cont, idnum, p)
    send_msg(plugin, peer_id, msgtype_term, idnum, parts[-1])


def send_result(plugin, peer_id, idnum, res):
    send_msgs(plugin, peer_id, idnum, res,
              HAWALA_OFFER_CONTINUES, HAWALA_OFFER_TERM)


def is_offer_valid(plugin, orderstr) -> Tuple[Optional[Dict], str]:
    """Is this order exists in the contract"""
    try:
        if type(orderstr) == str:
            order = json.loads(orderstr)
        elif type(orderstr) == dict:
            order = orderstr
        else:
            return None, 'Impossible order format'
        # formal offer check
        plugin.log(f"Checking order {order}")
    except Exception as e:  # noqa: E722
        plugin.log(f"Order error {e}")
        return None, 'Couldnt deserialize order data'

    return order, ''


def sync_offer(plugin, peer_id, data):
    if data is None:
        return {'error': 'No rune set?'}

    offer, err_msg = is_offer_valid(plugin, data)

    if not offer:
        plugin.log(f"Checking order {err_msg}")
        return {'error': err_msg}

    plugin.peer_offers[peer_id] = offer

    offer['peer'] = peer_id

    all_peers = [p['id'] for p in plugin.rpc.listpeers()['peers'] if p["connected"]]
    plugin.log(f"Broadcasting offer {offer} to {len(all_peers)} connected peers")
    for peer_to_sync in all_peers:
        if peer_to_sync != plugin.node_id:
            plugin.log(f"Sending offer to {peer_to_sync}")
            send_result(plugin, peer_to_sync, 1, offer)

    return {'result': {'offer': offer}}


@plugin.async_hook('custommsg')
def on_custommsg(peer_id, payload, plugin, request, **kwargs):
    pbytes = bytes.fromhex(payload)
    mtype = int.from_bytes(pbytes[:2], "big")
    idnum = int.from_bytes(pbytes[2:10], "big")
    data = pbytes[10:]
    # Here are methods for internode communications
    if mtype == HAWALA_OFFER_TERM:
        plugin.log(f"Received HAWALA_OFFER_TERM {idnum} {plugin.out_reqs}", level="debug")
        if idnum in plugin.out_reqs:
            # Big message
            plugin.out_reqs[idnum].buf += data
            finished = plugin.out_reqs[idnum]
            del plugin.out_reqs[idnum]

            try:
                ret = json.loads(finished.buf.decode())
            except Exception as e:
                # Bad response
                finished.req.set_exception(e)
                return {'result': 'continue'}

            if 'error' in ret:
                # Pass through error
                finished.req.set_exception(RpcError('hawala', {},
                                                    ret['error']))
            else:
                # Pass through result
                finished.req.set_result(ret['result'])
        else:
            # Short message
            plugin.log(f"Data received {data}")
            try:
                offer = json.loads(data)
                peer_id = offer.pop("peer")
                plugin.peer_offers[peer_id] = offer
            except Exception as e:
                plugin.log(f"Error while adding new offer {e}")
    elif mtype == HAWALA_TAKE:
        plugin.log(f"Received HAWALA_TAKE {idnum} {data}", level="debug")
        try:
            taker_data = json.loads(data)
            hashlock = taker_data.pop("hash")
            #invoice = plugin.rpc.invoice(999, label=f"h/{hashlock}", description="hawala invoice", expiry=1000,
            #                         preimage=None)
            invoices = plugin.rpc.listinvoices(payment_hash=hashlock)["invoices"]

            if len(invoices) != 1:
                plugin.log(f"Too many invoices", level="error")
                raise ValueError(f"Too many invoices with {hashlock}")

            plugin.log(f"Generated invoice & sending message with invoice", level="debug")
            parts = textwrap.wrap(json.dumps({"bolt11": invoices[0]['bolt11']}), 65000)
            if len(parts) > 1:
                plugin.log(f"Invoice is too long", level="error")
                raise ValueError(f"Invoice is too long")

            send_msg(plugin, peer_id, HAWALA_QUOTE, 0, parts[-1])
        except Exception as e:
            plugin.log(f"Error while processing taker data: {e}")
            request.set_result({'result': 'continue'})
            return

    elif mtype == HAWALA_QUOTE:
        plugin.log(f"Received HAWALA_QUOTE {idnum} {data}", level="debug")
        try:
            quote_data = json.loads(data)
            invoice = quote_data.pop("bolt11")
            pay_status = plugin.rpc.pay(invoice)

            plugin.log(f"Pay status {pay_status}", level="debug")

            if "status" in pay_status and pay_status["status"] != "complete":
                plugin.log(f"Couldnt pay invoice {invoice}", level="error")
                request.set_result({'result': 'continue'})
                return

            swap_status = plugin.rpc.call('bscredeemtokenhtlc', {'hashlock': pay_status["payment_hash"], "preimage": pay_status["payment_preimage"]})
            plugin.log(f"{swap_status}", level="debug")

        except Exception as e:
            plugin.log(f"Error while processing taker data: {e}")
            request.set_result({'result': 'continue'})
            return
    else:
        pass
    request.set_result({'result': 'continue'})


@plugin.subscribe('disconnect')
def on_disconnect(id, plugin, request, **kwargs):
    if id in plugin.in_reqs:
        del plugin.in_reqs[id]


@plugin.method("hawala-received")
def hawala_received(plugin):
    """This is intercepted by hawala runner, above"""
    raise RpcError('hawala-received', {},
                   'Must be called as a remote hawala call')


@plugin.method("hawala-create")
def hawala_create(plugin, data={}):
    """Createss new offer
    :param plugin:
    :param offer:
    :return:
    """
    if isinstance(data, dict) and data:
        sync_offer(plugin, plugin.node_id, data)
    else:
        raise RpcError('hawala-create', {},
                       'Provide offer')

    return {'offer': data}


@plugin.method("hawala-list")
def hawala_create(plugin):
    """List all received offers
    :param plugin:
    :param offer:
    :return:
    """
    return {'offers': plugin.peer_offers}


@plugin.method("hawala-take")
def hawala_create(plugin, hashlock):
    """List all received offers
    :param plugin:
    :param offer:
    :return:
    """
    plugin.log(f"Picking up order {hashlock}", level="info")
    peer_id = None

    for p, o in plugin.peer_offers.items():
        if "hashlock" in o and o["hashlock"] == hashlock:
            peer_id = p
        else:
            pass

    if peer_id:
        plugin.log(f"Sending HAWALA_TAKE {hashlock} to {peer_id}", level="debug")
        parts = textwrap.wrap(json.dumps({"hash": hashlock}), 65000)
        if len(parts) > 1:
            return {'error': 'Argument is too long'}
        send_msg(plugin, peer_id, HAWALA_TAKE, 0, parts[-1])
        return {'hash': hashlock}
    else:
        return {'error': 'No offer found'}


@plugin.init()
def init(options, configuration, plugin):
    plugin.out_reqs = {}
    plugin.in_reqs = {}
    # plugin.writers = options['hawala-writer']
    plugin.version = plugin.rpc.getinfo()['version']
    plugin.node_id = plugin.rpc.getinfo()['id']

    # dev-sendcustommsg was renamed to sendcustommsg for 0.10.1
    try:
        plugin.rpc.help('sendcustommsg')
        plugin.msgcmd = 'sendcustommsg'
    except RpcError:
        plugin.msgcmd = 'dev-sendcustommsg'

    plugin.peer_offers = {}
    plugin.log("Initialized without persistent orders)", level="info")


"""
plugin.add_option('hawala-writer',
                  description="What nodeid can do all commands?",
                  default=[],
                  multi=True)
"""
plugin.run()
