use core::mem;

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;
pub const ETH_P_ARP: u16 = 0x0806;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EthHdr {
    pub h_dest: [u8; 6],
    pub h_source: [u8; 6],
    pub h_proto: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ipv4Hdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

impl Ipv4Hdr {
    #[inline(always)]
    pub fn ihl_bytes(&self) -> usize {
        ((self.version_ihl & 0x0F) as usize) * 4
    }
}

pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_URG: u8 = 0x20;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TcpHdr {
    pub source: u16,
    pub dest: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub res1_doff: u8,
    pub flags: u8,
    pub window: u16,
    pub check: u16,
    pub urg_ptr: u16,
}

impl TcpHdr {
    #[inline(always)]
    pub fn is_syn(&self) -> bool {
        (self.flags & TCP_FLAG_SYN) != 0
    }

    #[inline(always)]
    pub fn is_ack(&self) -> bool {
        (self.flags & TCP_FLAG_ACK) != 0
    }

    #[inline(always)]
    pub fn is_fin_or_rst(&self) -> bool {
        (self.flags & (TCP_FLAG_FIN | TCP_FLAG_RST)) != 0
    }

    #[inline(always)]
    pub fn doff_bytes(&self) -> usize {
        ((self.res1_doff >> 4) as usize) * 4
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct UdpHdr {
    pub source: u16,
    pub dest: u16,
    pub len: u16,
    pub check: u16,
}

#[inline(always)]
pub unsafe fn ptr_at<T>(data: usize, data_end: usize, offset: usize) -> Result<*const T, ()> {
    if data + offset + mem::size_of::<T>() > data_end {
        return Err(());
    }
    Ok((data + offset) as *const T)
}

#[inline(always)]
pub unsafe fn ptr_at_mut<T>(data: usize, data_end: usize, offset: usize) -> Result<*mut T, ()> {
    if data + offset + mem::size_of::<T>() > data_end {
        return Err(());
    }
    Ok((data + offset) as *mut T)
}
