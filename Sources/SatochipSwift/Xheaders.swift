//
//  File.swift
//  
//
//  Created by Satochip on 29/04/2024.
//

import Foundation

// based on https://github.com/spesmilo/electrum/blob/master/electrum/constants.py
public enum XPUB_HEADERS_MAINNET: UInt32 {
    case standard =    0x0488b21e  // xpub
    case p2wpkh_p2sh = 0x049d7cb2  // ypub
    case p2wsh_p2sh =  0x0295b43f  // Ypub
    case p2wpkh =      0x04b24746  // zpub
    case p2wsh =       0x02aa7ed3  // Zpub
}

public enum XPUB_HEADERS_TESTNET: UInt32 {
    case standard =    0x043587cf  // tpub
    case p2wpkh_p2sh = 0x044a5262  // upub
    case p2wsh_p2sh =  0x024289ef  // Upub
    case p2wpkh =      0x045f1cf6  // vpub
    case p2wsh =       0x02575483  // Vpub
}

public enum XPRV_HEADERS_MAINNET: UInt32 {
    case standard =    0x0488ade4  // xprv
    case p2wpkh_p2sh = 0x049d7878  // yprv
    case p2wsh_p2sh =  0x0295b005  // Yprv
    case p2wpkh =      0x04b2430c  // zprv
    case p2wsh =       0x02aa7a99  // Zprv
}

public enum XPRV_HEADERS_TESTNET: UInt32 {
    case standard =    0x04358394  // tprv
    case p2wpkh_p2sh = 0x044a4e28  // uprv
    case p2wsh_p2sh =  0x024285b5  // Uprv
    case p2wpkh =      0x045f18bc  // vprv
    case p2wsh =       0x02575048  // Vprv
}
