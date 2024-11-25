-- | An implementation of the Modbus TPC/IP protocol.
--
-- This implementation is based on the @MODBUS Application Protocol
-- Specification V1.1b@
-- (<http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf>).
module System.Modbus.TCP
  ( -- * Session Monad
    Session
  , runSession

    -- * Connections
  , Connection(..)

    -- * Types
  , ADU(..)
  , HeaderRTU(..)
  , HeaderTCP(..)
  , FunctionCode(..)
  , ExceptionCode(..)
  , ModbusException(..)
  , ModbusVariation(..)
  , ModbusRTU
  , ModbusTCP

  , TransactionId(..)
  , ProtocolId(..)
  , UnitId(..)
  , SlaveId(..)
  , RegAddress(..)

  , RetryPredicate

    -- * Commands
  , command

  , readCoils
  , readDiscreteInputs
  , readHoldingRegisters
  , readInputRegisters
  , writeSingleCoil
  , writeSingleRegister
  , writeMultipleRegisters
  ) where

import "base" Control.Exception.Base ( Exception )
import "base" Control.Monad ( replicateM, mzero )
import "base" Control.Monad.IO.Class ( MonadIO, liftIO )
import Data.Array
import Data.Bits
import "base" Data.Bool ( bool )
import "base" Data.Functor ( void )
import "base" Data.Word ( Word8, Word16 )
import "base" Data.Typeable ( Typeable, Proxy(..) )
import "base" System.Timeout ( timeout )
import Data.List (foldl')
import qualified "cereal" Data.Serialize as Cereal ( encode, decode )
import "cereal" Data.Serialize
  ( Serialize, Put, put, Get, get
  , runPut, runGet
  , putWord8, putWord16be, putWord16host
  , getWord8, getWord16be, getWord16host
  , getByteString
  , remaining
  )
import "bytestring" Data.ByteString ( ByteString )
import qualified "bytestring" Data.ByteString as BS
import "mtl" Control.Monad.Reader ( MonadReader, ask )
import "mtl" Control.Monad.Except ( MonadError, throwError, catchError )
import "transformers" Control.Monad.Trans.Class ( lift )
import "transformers" Control.Monad.Trans.Except
    ( ExceptT(ExceptT), withExceptT )
import "transformers" Control.Monad.Trans.Reader
    ( ReaderT, runReaderT )

newtype TransactionId
      = TransactionId { unTransactionId :: Word16 }
        deriving (Eq, Num, Ord, Read, Show)

newtype ProtocolId
      = ProtocolId { unProtocolId :: Word16 }
        deriving (Eq, Num, Ord, Read, Show)

newtype UnitId
      = UnitId { unUnitId :: Word8 }
        deriving (Bounded, Enum, Eq, Num, Ord, Read, Show)

newtype SlaveId
      = SlaveId { unSlaveId :: Word8 }
        deriving (Bounded, Enum, Eq, Num, Ord, Read, Show)

newtype RegAddress
      = RegAddress { unRegAddress :: Word16 }
        deriving (Bounded, Enum, Eq, Num, Ord, Read, Show)

type RetryPredicate
   =  Int -- ^ Number of tries.
   -> ModbusException
      -- ^ Exception raised by the latest attempt to execute a command.
   -> Bool
      -- ^ If 'True' the command will be retried, if 'False' the
      -- aforementioned 'ModbusException' will be rethrown.

data Connection
   = Connection
     { connWrite :: !(BS.ByteString -> IO Int)
       -- ^ Action that writes bytes.
       --
       -- You can use Network.Socket.ByteString.send applied to some
       -- socket, or some custom function.
     , connRead :: !(Int -> IO BS.ByteString)
       -- ^ Action that reads bytes.
       --
       -- You can use Network.Socket.ByteString.recv applied to some
       -- socket, or some custom function.
     , connCommandTimeout :: !Int
       -- ^ Time limit in microseconds for each command.
     , connRetryWhen :: !RetryPredicate
       -- ^ Predicate that determines whether a failed command should
       -- be retried.
     }

-- | Modbus TCP session monad.
newtype Session a
      = Session
        { runSession' :: ReaderT Connection (ExceptT ModbusException IO) a
        } deriving ( Functor
                   , Applicative
                   , Monad
                   , MonadError ModbusException
                   , MonadReader Connection
                   , MonadIO
                   )

-- | Run a session using a connection.
runSession :: Connection -> Session a -> ExceptT ModbusException IO a
runSession conn session = runReaderT (runSession' session) conn

data ModbusTCP

data ModbusRTU

class (Serialize (HeaderType a)
      ,Eq (HeaderType a)
      ,Show (HeaderType a)
      ,Serialize (CrcType a)
      ,Eq (CrcType a)
      ,Show (CrcType a)) =>
  ModbusVariation a where
  type HeaderType a
  type CrcType a
  crcFunction :: Proxy a -> ByteString -> CrcType a
  getFrameBodyLength :: Proxy a -> HeaderType a -> Get Int
  adjustHeader :: Proxy a -> ByteString -> HeaderType a -> HeaderType a
  nextTransaction :: Proxy a -> HeaderType a -> HeaderType a

instance ModbusVariation ModbusTCP where
  type HeaderType ModbusTCP = HeaderTCP
  type CrcType ModbusTCP = ()
  crcFunction _ _ = ()
  getFrameBodyLength _ header = pure $ fromIntegral (hdrtcpLength header) - 2
  adjustHeader _ fdata header = header { hdrtcpLength = fromIntegral $ 2 + BS.length fdata }
  nextTransaction _ header = header { hdrtcpTransactionId = 1 + hdrtcpTransactionId header }

newtype ModbusCRC = ModbusCRC { unModbusCRC :: Word16 } deriving (Eq, Show)

instance Serialize ModbusCRC where
  get = ModbusCRC <$> getWord16host
  put = putWord16host . unModbusCRC

instance ModbusVariation ModbusRTU where
  type HeaderType ModbusRTU = HeaderRTU
  type CrcType ModbusRTU = ModbusCRC
  -- https://github.com/jhickner/haskell-modbus/blob/master/Data/Digest/CRC16.hs
  crcFunction _ = ModbusCRC . foldl' f 0xFFFF . BS.unpack
    where
      f ac v = (ac `shiftR` 8) `xor` (table ! idx)
        where idx = (fromIntegral v `xor` ac) .&. 0xFF
      table :: Array Word16 Word16
      table = listArray (0,255) tableList
      tableList :: [Word16]
      tableList =
        [0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241
        ,0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440
        ,0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40
        ,0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841
        ,0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40
        ,0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41
        ,0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641
        ,0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040
        ,0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240
        ,0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441
        ,0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41
        ,0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840
        ,0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41
        ,0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40
        ,0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640
        ,0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041
        ,0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240
        ,0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441
        ,0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41
        ,0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840
        ,0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41
        ,0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40
        ,0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640
        ,0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041
        ,0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241
        ,0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440
        ,0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40
        ,0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841
        ,0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40
        ,0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41
        ,0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641
        ,0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040]
  getFrameBodyLength _ _ = (\x -> x - 2) <$> remaining
  adjustHeader _ _ = id
  nextTransaction _ = id

-- | MODBUS TCP/IP Application Data Unit
--
-- See: MODBUS Application Protocol Specification V1.1b, section 4.1
data ADU v
   = (ModbusVariation v) => ADU
     { aduProxy    :: Proxy v
     , aduHeader   :: !(HeaderType v)
     , aduFunction :: !FunctionCode
     , aduData     :: !ByteString
     , aduCrc      :: !(CrcType v)
     }

deriving instance ModbusVariation v => Eq (ADU v)
deriving instance ModbusVariation v => Show (ADU v)

instance (ModbusVariation v) => Serialize (ADU v) where
  put (ADU _ header fc ws crc) = do
      put header
      put fc
      mapM_ putWord8 (BS.unpack ws)
      put crc

  get = do
      header <- get
      fc     <- get
      ws     <- getFrameBodyLength (Proxy @v) header >>= getByteString
      crc    <- get
      return $ ADU (Proxy @v) header fc ws crc

-- | MODBUS Application Protocol Header
--
-- See: MODBUS Application Protocol Specification V1.1b, section 4.1
data HeaderTCP =
  HeaderTCP
  { hdrtcpTransactionId :: !TransactionId
  , hdrtcpProtocolId    :: !ProtocolId
  , hdrtcpLength        :: !Word16
  , hdrtcpUnitId        :: !UnitId
  }
  deriving (Eq,Show)
data HeaderRTU =
  HeaderRTU
  { hdrrtuSlaveId :: !SlaveId
  }
  deriving (Eq, Show)

instance Serialize HeaderTCP where
    put (HeaderTCP (TransactionId tid) (ProtocolId pid) len (UnitId uid)) =
      putWord16be tid >> putWord16be pid >> putWord16be len >> putWord8 uid
    get = HeaderTCP
          <$> (TransactionId <$> getWord16be)
          <*> (ProtocolId    <$> getWord16be)
          <*> getWord16be
          <*> (UnitId <$> getWord8)

instance Serialize HeaderRTU where
    put (HeaderRTU (SlaveId sid)) =
      putWord8 sid
    get = HeaderRTU . SlaveId <$> getWord8

-- | The function code field of a MODBUS data unit is coded in one
-- byte. Valid codes are in the range of 1 ... 255 decimal (the range
-- 128 - 255 is reserved and used for exception responses). When a
-- message is sent from a Client to a Server device the function code
-- field tells the server what kind of action to perform. Function
-- code 0 is not valid.
--
-- Sub-function codes are added to some function codes to define
-- multiple actions.
--
-- See: MODBUS Application Protocol Specification V1.1b, sections 4.1 and 5
data FunctionCode
   = -- | See: MODBUS Application Protocol Specification V1.1b, section 6.1
     ReadCoils
     -- | See: MODBUS Application Protocol Specification V1.1b, section 6.2
   | ReadDiscreteInputs
     -- | See: MODBUS Application Protocol Specification V1.1b, section 6.3
   | ReadHoldingRegisters
     -- | See: MODBUS Application Protocol Specification V1.1b, section 6.4
   | ReadInputRegisters
     -- | See: MODBUS Application Protocol Specification V1.1b, section 6.5
   | WriteSingleCoil
     -- | See: MODBUS Application Protocol Specification V1.1b, section 6.6
   | WriteSingleRegister
     -- | See: MODBUS Application Protocol Specification V1.1b, section 6.7
   | ReadExceptionStatus
     -- | See: MODBUS Application Protocol Specification V1.1b, section 6.8
   | Diagnostics
     -- | See: MODBUS Application Protocol Specification V1.1b, section 6.9
   | GetCommEventCounter
     -- | See: MODBUS Application Protocol Specification V1.1b, section 6.10
   | GetCommEventLog
     -- | See: MODBUS Application Protocol Specification V1.1b, section 6.11
   | WriteMultipleCoils
     -- | See: MODBUS Application Protocol Specification V1.1b, section 6.12
   | WriteMultipleRegisters
     -- | See: MODBUS Application Protocol Specification V1.1b, section 6.13
   | ReportSlaveID
     -- | See: MODBUS Application Protocol Specification V1.1b, section 6.14
   | ReadFileRecord
     -- | See: MODBUS Application Protocol Specification V1.1b, section 6.15
   | WriteFileRecord
     -- | See: MODBUS Application Protocol Specification V1.1b, section 6.16
   | MaskWriteRegister
     -- | See: MODBUS Application Protocol Specification V1.1b, section 6.17
   | ReadWriteMultipleRegisters
     -- | See: MODBUS Application Protocol Specification V1.1b, section 6.18
   | ReadFIFOQueue
     -- | See: MODBUS Application Protocol Specification V1.1b, section 6.19
   | EncapsulatedInterfaceTransport
     -- | See: MODBUS Application Protocol Specification V1.1b, section 5
   | UserDefinedCode Word8
     -- | See: MODBUS Application Protocol Specification V1.1b, section 5
   | ReservedCode Word8
   | OtherCode Word8
   | ExceptionCode FunctionCode
     deriving (Eq, Show)

instance Serialize FunctionCode where
  put = putWord8 . enc
    where
      enc :: FunctionCode -> Word8
      enc ReadCoils                      = 0x01
      enc ReadDiscreteInputs             = 0x02
      enc ReadHoldingRegisters           = 0x03
      enc ReadInputRegisters             = 0x04
      enc WriteSingleCoil                = 0x05
      enc WriteSingleRegister            = 0x06
      enc ReadExceptionStatus            = 0x07
      enc Diagnostics                    = 0x08
      enc GetCommEventCounter            = 0x0B
      enc GetCommEventLog                = 0x0C
      enc WriteMultipleCoils             = 0x0F
      enc WriteMultipleRegisters         = 0x10
      enc ReportSlaveID                  = 0x11
      enc ReadFileRecord                 = 0x14
      enc WriteFileRecord                = 0x15
      enc MaskWriteRegister              = 0x16
      enc ReadWriteMultipleRegisters     = 0x17
      enc ReadFIFOQueue                  = 0x18
      enc EncapsulatedInterfaceTransport = 0x2B
      enc (UserDefinedCode   code)       = code
      enc (ReservedCode      code)       = code
      enc (OtherCode         code)       = code
      enc (ExceptionCode fc)             = 0x80 + enc fc

  get = getWord8 >>= return . dec
    where
      dec :: Word8 -> FunctionCode
      dec 0x01 = ReadCoils
      dec 0x02 = ReadDiscreteInputs
      dec 0x03 = ReadHoldingRegisters
      dec 0x04 = ReadInputRegisters
      dec 0x05 = WriteSingleCoil
      dec 0x06 = WriteSingleRegister
      dec 0x07 = ReadExceptionStatus
      dec 0x08 = Diagnostics
      dec 0x0B = GetCommEventCounter
      dec 0x0C = GetCommEventLog
      dec 0x0F = WriteMultipleCoils
      dec 0x10 = WriteMultipleRegisters
      dec 0x11 = ReportSlaveID
      dec 0x14 = ReadFileRecord
      dec 0x15 = WriteFileRecord
      dec 0x16 = MaskWriteRegister
      dec 0x17 = ReadWriteMultipleRegisters
      dec 0x18 = ReadFIFOQueue
      dec 0x2B = EncapsulatedInterfaceTransport
      dec code |    (code >=  65 && code <=  72)
                 || (code >= 100 && code <= 110) = UserDefinedCode code
               | code `elem` [9, 10, 13, 14, 41, 42, 90, 91, 125, 126, 127]
                 = ReservedCode code
               | code >= 0x80 = ExceptionCode $ dec $ code - 0x80
               | otherwise = OtherCode code

-- | See: MODBUS Application Protocol Specification V1.1b, section 7
data ExceptionCode
   = -- | The function code received in the query is not an allowable
     -- action for the server (or slave). This may be because the
     -- function code is only applicable to newer devices, and was not
     -- implemented in the unit selected. It could also indicate that
     -- the server (or slave) is in the wrong state to process a
     -- request of this type, for example because it is unconfigured
     -- and is being asked to return register values.
     IllegalFunction
     -- | The data address received in the query is not an allowable
     -- address for the server (or slave). More specifically, the
     -- combination of reference number and transfer length is
     -- invalid. For a controller with 100 registers, the PDU addresses
     -- the first register as 0, and the last one as 99. If a request
     -- is submitted with a starting register address of 96 and a
     -- quantity of registers of 4, then this request will successfully
     -- operate (address-wise at least) on registers 96, 97, 98, 99. If
     -- a request is submitted with a starting register address of 96
     -- and a quantity of registers of 5, then this request will fail
     -- with Exception Code 0x02 \"Illegal Data Address\" since it
     -- attempts to operate on registers 96, 97, 98, 99 and 100, and
     -- there is no register with address 100.
   | IllegalDataAddress
     -- | A value contained in the query data field is not an allowable
     -- value for server (or slave). This indicates a fault in the
     -- structure of the remainder of a complex request, such as that
     -- the implied length is incorrect. It specifically does NOT mean
     -- that a data item submitted for storage in a register has a
     -- value outside the expectation of the application program, since
     -- the MODBUS protocol is unaware of the significance of any
     -- particular value of any particular register.
   | IllegalDataValue
     -- | An unrecoverable error occurred while the server (or slave)
     -- was attempting to perform the requested action.
   | SlaveDeviceFailure
     -- | Specialized use in conjunction with programming commands. The
     -- server (or slave) has accepted the request and is processing
     -- it, but a long duration of time will be required to do so. This
     -- response is returned to prevent a timeout error from occurring
     -- in the client (or master). The client (or master) can next
     -- issue a Poll Program Complete message to determine if
     -- processing is completed.
   | Acknowledge
     -- | Specialized use in conjunction with programming commands. The
     -- server (or slave) is engaged in processing a long–duration
     -- program command. The client (or master) should retransmit the
     -- message later when the server (or slave) is free.
   | SlaveDeviceBusy
     -- | Specialized use in conjunction with function codes
     -- 'ReadFileRecord' and 'WriteFileRecord' and reference type 6, to
     -- indicate that the extended file area failed to pass a
     -- consistency check.
   | MemoryParityError
     -- | Specialized use in conjunction with gateways, indicates that
     -- the gateway was unable to allocate an internal communication
     -- path from the input port to the output port for processing the
     -- request. Usually means that the gateway is misconfigured or
     -- overloaded.
   | GatewayPathUnavailable
     -- | Specialized use in conjunction with gateways, indicates that
     -- no response was obtained from the target device. Usually means
     -- that the device is not present on the network.
   | GatewayTargetDeviceFailedToRespond
     deriving (Eq, Show)

instance Serialize ExceptionCode where
  put = putWord8 . enc
    where
      enc IllegalFunction                    = 0x01
      enc IllegalDataAddress                 = 0x02
      enc IllegalDataValue                   = 0x03
      enc SlaveDeviceFailure                 = 0x04
      enc Acknowledge                        = 0x05
      enc SlaveDeviceBusy                    = 0x06
      enc MemoryParityError                  = 0x08
      enc GatewayPathUnavailable             = 0x0A
      enc GatewayTargetDeviceFailedToRespond = 0x0B

  get = getWord8 >>= dec
    where
      dec 0x01 = return IllegalFunction
      dec 0x02 = return IllegalDataAddress
      dec 0x03 = return IllegalDataValue
      dec 0x04 = return SlaveDeviceFailure
      dec 0x05 = return Acknowledge
      dec 0x06 = return SlaveDeviceBusy
      dec 0x08 = return MemoryParityError
      dec 0x0A = return GatewayPathUnavailable
      dec 0x0B = return GatewayTargetDeviceFailedToRespond
      dec _    = mzero

data ModbusException
   = ExceptionResponse !FunctionCode !ExceptionCode
   | DecodeException !String
   | CommandTimeout
     -- ^ A command took longer than 'connCommandTimeout'
     -- microseconds.
   | OtherException !String
     deriving (Eq, Show, Typeable)

instance Exception ModbusException

-- | Sends a raw MODBUS command.
command
    :: forall v. (ModbusVariation v)
    => Proxy v
    -> HeaderType v
    -> FunctionCode -- ^ PDU function code.
    -> ByteString   -- ^ PDU data.
    -> Session (ADU v)
command proxy hdr fc fdata = do
    conn <- ask
    Session $ lift $ withConn conn
  where
    withConn :: Connection -> ExceptT ModbusException IO (ADU v)
    withConn conn = go 1
      where
        go :: Int -> ExceptT ModbusException IO (ADU v)
        go !tries =
            catchError
              (command' conn proxy hdr fc fdata)
              (\err ->
                bool (throwError err)
                     (go $ tries + 1)
                     (connRetryWhen conn tries err)
              )

command'
    :: forall v. (ModbusVariation v)
    => Connection
    -> Proxy v
    -> HeaderType v
    -> FunctionCode -- ^ PDU function code.
    -> ByteString   -- ^ PDU data.
    -> ExceptT ModbusException IO (ADU v)
command' conn proxy hdr fc fdata = do
    mbResult <- liftIO $ timeout (connCommandTimeout conn) $ do
      void $ connWrite conn (Cereal.encode cmd)
      connRead conn 512
    result <- maybe (throwError CommandTimeout) pure mbResult

    adu <- withExceptT DecodeException $ ExceptT $ pure $ Cereal.decode result
    case aduFunction adu of
      ExceptionCode rc ->
          throwError
            $ either DecodeException (ExceptionResponse rc)
            $ Cereal.decode (aduData adu)
      _ -> pure adu
  where
    header :: HeaderType v
    header = adjustHeader proxy fdata hdr
    cmd = ADU proxy header fc fdata crc
    crc :: CrcType v
    crc = crcFunction proxy (Cereal.encode header <> Cereal.encode fc <> fdata)

readCoils
    :: (ModbusVariation v)
    => Proxy v
    -> HeaderType v
    -> RegAddress
    -> Word16
    -> Session [Word8]
readCoils proxy hdr addr count =
    withAduData proxy hdr ReadCoils
                (putRegAddress addr >> putWord16be count)
                decodeW8s

readDiscreteInputs
    :: (ModbusVariation v)
    => Proxy v
    -> HeaderType v
    -> RegAddress
    -> Word16
    -> Session [Word8]
readDiscreteInputs proxy hdr addr count =
    withAduData proxy hdr ReadDiscreteInputs
                (putRegAddress addr >> putWord16be count)
                decodeW8s

readHoldingRegisters
    :: (ModbusVariation v)
    => Proxy v
    -> HeaderType v
    -> RegAddress -- ^ Register starting address.
    -> Word16 -- ^ Quantity of registers.
    -> Session [Word16]
readHoldingRegisters proxy hdr addr count =
    withAduData proxy hdr ReadHoldingRegisters
                (putRegAddress addr >> putWord16be count)
                decodeW16s

readInputRegisters
    :: (ModbusVariation v)
    => Proxy v
    -> HeaderType v
    -> RegAddress -- ^ Starting address.
    -> Word16 -- ^ Quantity of input registers.
    -> Session [Word16]
readInputRegisters proxy hdr addr count =
    withAduData proxy hdr ReadInputRegisters
                (putRegAddress addr >> putWord16be count)
                decodeW16s

writeSingleCoil
    :: (ModbusVariation v)
    => Proxy v
    -> HeaderType v
    -> RegAddress
    -> Bool
    -> Session ()
writeSingleCoil proxy hdr addr value =
    void $ command proxy hdr WriteSingleCoil
                   (runPut $ putRegAddress addr >> putWord16be value')
  where
    value' | value     = 0xFF00
           | otherwise = 0x0000

writeSingleRegister
    :: (ModbusVariation v)
    => Proxy v
    -> HeaderType v
    -> RegAddress -- ^ Register address.
    -> Word16 -- ^ Register value.
    -> Session ()
writeSingleRegister proxy hdr addr value =
    void $ command proxy hdr WriteSingleRegister
                   (runPut $ putRegAddress addr >> putWord16be value)

writeMultipleRegisters
    :: (ModbusVariation v)
    => Proxy v
    -> HeaderType v
    -> RegAddress -- ^ Register starting address
    -> [Word16] -- ^ Register values to be written
    -> Session Word16
writeMultipleRegisters proxy hdr addr values =
    withAduData proxy hdr WriteMultipleRegisters
                (do putRegAddress addr
                    putWord16be $ fromIntegral numRegs
                    putWord8    $ fromIntegral numRegs
                    mapM_ putWord16be values
                )
                (getWord16be >> getWord16be)
  where
    numRegs :: Int
    numRegs = length values

--------------------------------------------------------------------------------

withAduData
    :: (ModbusVariation v)
    => Proxy v
    -> HeaderType v
    -> FunctionCode
    -> Put -- ^ PDU data
    -> Get a -- ^ Parser of resulting 'aduData'
    -> Session a
withAduData proxy hdr fc fdata parser = do
    adu <- command proxy hdr fc (runPut fdata)
    Session $ lift $ withExceptT DecodeException $ ExceptT $ pure $ runGet parser $ aduData adu

putRegAddress :: RegAddress -> Put
putRegAddress = putWord16be . unRegAddress

decodeW8s :: Get [Word8]
decodeW8s = do n <- getWord8
               replicateM (fromIntegral n) getWord8

decodeW16s :: Get [Word16]
decodeW16s = do n <- getWord8
                replicateM (fromIntegral $ n `div` 2) getWord16be
