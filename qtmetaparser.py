# Qt5 Ida pro 8.3 portable
#Python 3.11.7 (tags/v3.11.7:fa7a6f2, Dec  4 2023, 19:24:49) [MSC v.1937 64 bit (AMD64)] 
#IDAPython v7.4.0 final (serial 0) (c) The IDAPython Team <idapython@googlegroups.com>

import idc
import ida_bytes
import ida_xref
import ida_name


if idc.__EA64__:
    ARCH_F = ida_bytes.FF_QWORD | FF_DATA
else:
    ARCH_F = ida_bytes.FF_DWORD | FF_DATA


type_maker = {1: idc.get_wide_byte, 2:  idc.get_wide_word, 4: idc.get_wide_dword, 8: idc.get_qword}

def struct_adder(cls, mapper):
    if ida_struct.get_struc_id(cls.__name__) == BADADDR:
        # idx = GetLastStrucIdx() + 1
        idx = -1
        sid = idc.add_struc(idx, cls.__name__, 0)
        cls.sid = sid
        for member in mapper:
            type_flag = member[1]
            if ida_bytes.is_off0(type_flag):
                reftype = REF_OFF64 if ida_bytes.is_qword(ARCH_F) else REF_OFF32
                idc.add_struc_member(sid, member[0], -1, type_flag, 0, get_bytes_size(type_flag), reftype=reftype)
            else:
                idc.add_struc_member(sid, member[0], -1, type_flag, -1, get_bytes_size(type_flag))
    else:
        cls.sid = ida_struct.get_struc_id(cls.__name__)


def struct_maker(obj, off):
    struct_adder(obj.__class__, obj.c_struct)
    ida_bytes.del_items(off, ida_struct.get_struc_size(obj.__class__.sid), ida_bytes.DELIT_EXPAND)
    idc.create_struct(off, -1, ida_struct.get_struc_name(obj.__class__.sid))


# noinspection PyPep8Naming
class QMetaObjectPrivate:
    """
struct QMetaObjectPrivate
{
    // revision 7 is Qt 5.0 everything lower is not supported
    enum { OutputRevision = 7 }; // Used by moc, qmetaobjectbuilder and qdbus

    int revision;
    int className;
    int classInfoCount, classInfoData;
    int methodCount, methodData;
    int propertyCount, propertyData;
    int enumeratorCount, enumeratorData;
    int constructorCount, constructorData;
    int flags;
    int signalCount;
    enum DisconnectType { DisconnectAll, DisconnectOne };
};

QMetaMethod QMetaObject::method(int index) const
{
    int i = index;
    i -= methodOffset();
    if (i < 0 && d.superdata)
        return d.superdata->method(index);

    QMetaMethod result;
    if (i >= 0 && i < priv(d.data)->methodCount) {
        result.mobj = this;
        result.handle = priv(d.data)->methodData + 5*i;
    }
    return result;
}


"""
    c_struct = [("revision", FF_DATA | ida_bytes.FF_DWORD),
                ("className", FF_DATA | ida_bytes.FF_DWORD),
                ("classInfoCount", FF_DATA | ida_bytes.FF_DWORD),
                ("classInfoData", FF_DATA | ida_bytes.FF_DWORD),
                ("methodCount", FF_DATA | ida_bytes.FF_DWORD),
                ("methodData", FF_DATA | ida_bytes.FF_DWORD),
                ("propertyCount", FF_DATA | ida_bytes.FF_DWORD),
                ("propertyData", FF_DATA | ida_bytes.FF_DWORD),
                ("enumeratorCount", FF_DATA | ida_bytes.FF_DWORD),
                ("enumeratorData", FF_DATA | ida_bytes.FF_DWORD),
                ("constructorCount", FF_DATA | ida_bytes.FF_DWORD),
                ("constructorData", FF_DATA | ida_bytes.FF_DWORD),
                ("flags", FF_DATA | ida_bytes.FF_DWORD),
                ("signalCount", FF_DATA | ida_bytes.FF_DWORD)]

    # todo: when superdata is not null
    def __init__(self, offset, str_data):
        self.offset = offset
        struct_map(self, self.c_struct, offset)
        struct_maker(self, offset)
        cmmt = """CLASS: %s
MethodCount: %d PropertyCount: %d EnumCount: %d
ConstructorCount: %d SignalCount: %d""" % (str_data[self.className].string,
    self.methodCount, self.propertyCount, self.enumeratorCount,
    self.constructorCount, self.signalCount)
        # print(cmmt)
        # S = 'ExtLinB(%d, 0, "%s")' % (offset, cmmt)
        # print(S)
        # idaapi.run_statements(S)
        idc.set_cmt(offset, cmmt, 0)


def displayMetaDataForStaticMetaObj():
    # get import entry
    def getImpStaticMetaObjectFromIdata():
        import ida_nalt
        staticMetaObject_imp_idata_eas = []

        nimps = ida_nalt.get_import_module_qty()
        
        for i in range(nimps):
            name = ida_nalt.get_import_module_name(i)
            if not name:
                print("Failed to get import module name for #%d" % i)
                name = "<unnamed>"
            if name != "Qt5Core":
                continue
        
            print("Walking imports for module name %s" % name)
            def imp_cb(ea, name, ordinal):
                nonlocal staticMetaObject_imp_idata_eas
                # if not name:
                #     print("%08x: ordinal #%d" % (ea, ordinal))
                # else:
                #     print("%08x: %s (ordinal #%d)" % (ea, name, ordinal))
                # True -> Continue enumeration
                # False -> Stop enumeration
                # TODO: return supported xxx:staticMetaObject
                if name == "?dynamicMetaObject@QObjectData@@QBEPAUQMetaObject@@XZ": # QObjectData::dynamicMetaObject(void)	Qt5Core
                    staticMetaObject_imp_idata_eas.append(ea)
                return True
            ida_nalt.enum_import_names(i, imp_cb)
        if len(staticMetaObject_imp_idata_eas) == 0:
            raise Exception("not able to find xxx::dynamicMetaObject")
        return staticMetaObject_imp_idata_eas
    
    
    staticMetaObject_eas = getImpStaticMetaObjectFromIdata()
    print("staticMetaObject_eas", staticMetaObject_eas)
    for staticMetaObject_ea in staticMetaObject_eas:
        xb = ida_xref.xrefblk_t()
        for cref in xb.crefs_to(staticMetaObject_ea):
            print(f"currCref is {hex(cref)}")
            staticMetaObjArr = []
            end = idc.get_func_attr(cref, FUNCATTR_END)
            cur_addr = cref
            while cur_addr < end:
                if idc.print_insn_mnem(cur_addr).lower() == "mov":
                    cur0_type = idc.get_operand_type(cur_addr, 0)
                    cur0_value = idc.get_operand_value(cur_addr, 0)
                    cur1_type = idc.get_operand_type(cur_addr, 1)
                    cur1_value = idc.get_operand_value(cur_addr, 1)
                    if cur0_type == o_displ and cur1_type == o_imm:  # mov     [ebp+var_8], offset off_66D574
                        if idc.get_operand_value(cur1_value, 0) == o_displ:
                            staticMetaObjArr.append(cur1_value)
                cur_addr = idc.next_head(cur_addr,end)
            print(f"staticMetaObjArr {staticMetaObjArr}")
            if len(staticMetaObjArr) == 0:
                print(f"no applicable staticMetaObj from {hex(cref)}")
                continue
            assert len(staticMetaObjArr) == 1
            parser = QtMetaParser(d_offset=staticMetaObjArr[0], is_dynamic=False)
            parser.make_qmetaobjecprivate()


def displayMetaDataForDynamicMetaObj():
    # get import entry
    def getImpStaticMetaObjectFromIdata():
        import ida_nalt
        staticMetaObject_imp_idata_eas = []

        nimps = ida_nalt.get_import_module_qty()
        
        for i in range(nimps):
            name = ida_nalt.get_import_module_name(i)
            if not name:
                print("Failed to get import module name for #%d" % i)
                name = "<unnamed>"
            if not name.startswith("Qt5"):
                continue
        
            print("Walking imports for module name %s" % name)
            def imp_cb(ea, name, ordinal):
                nonlocal staticMetaObject_imp_idata_eas
                qclassNames = ["QObject", "QThread", "QWidget", "QGraphicsEffect", "QDialog", "QStyledItemDelegate", "QMenu", "QListWidget"]
                # if not name:
                #     print("%08x: ordinal #%d" % (ea, ordinal))
                # else:
                #     print("%08x: %s (ordinal #%d)" % (ea, name, ordinal))
                # True -> Continue enumeration
                # False -> Stop enumeration
                # TODO: return supported xxx:staticMetaObject
                if name.startswith("?staticMetaObject@"): # QObject::staticMetaObject
                    for qclass in qclassNames:
                        if qclass in name: staticMetaObject_imp_idata_eas.append(ea)
                return True
            ida_nalt.enum_import_names(i, imp_cb)
        if len(staticMetaObject_imp_idata_eas) == 0:
            raise Exception("not able to find xxx::staticMetaObject")
        return staticMetaObject_imp_idata_eas
    
    
    staticMetaObject_eas = getImpStaticMetaObjectFromIdata()
    print("staticMetaObject_eas", staticMetaObject_eas)
    for staticMetaObject_ea in staticMetaObject_eas:
        xb = ida_xref.xrefblk_t()
        for dref in xb.drefs_to(staticMetaObject_ea):
            print(f"currDref is {hex(dref)}")
            currFuncArry = []
            end = idc.get_func_attr(dref, FUNCATTR_END)
            cur_addr = dref
            while cur_addr < end:
                if idc.print_insn_mnem(cur_addr).lower() == "mov":
                    prev_addr = idc.prev_head(cur_addr, dref)
                    has_prev_addr = prev_addr != BADADDR
                    cur0_type = idc.get_operand_type(cur_addr, 0)
                    cur0_value = idc.get_operand_value(cur_addr, 0)
                    cur1_type = idc.get_operand_type(cur_addr, 1)
                    cur1_value = idc.get_operand_value(cur_addr, 1)
                    if cur0_type == o_mem and cur1_type == o_reg:  # mov     dword_6D2B2C, eax
                        if has_prev_addr:  # look back for mov  eax, ds:?staticMetaObject@QObject@@2UQMetaObject@@B
                            prev0_type = idc.get_operand_type(prev_addr, 0)
                            prev0_value = idc.get_operand_value(prev_addr, 0)
                            prev1_type = idc.get_operand_type(prev_addr, 1)
                            prev1_value = idc.get_operand_value(prev_addr, 1)
                            if prev0_value == cur1_value and prev0_type == cur1_type:
                                currFuncArry.append((cur0_value,prev1_value))
                    if cur0_type == o_mem and cur1_type == o_imm:  # mov     dword_6D2B30, offset unk_670F84
                        currFuncArry.append((cur0_value, cur1_value))
                cur_addr = idc.next_head(cur_addr,end)
            print(f"currFuncArry {currFuncArry}")  # [(loc, value), (loc, value)]
            
            parser = QtMetaParser(currFuncArr=currFuncArry, is_dynamic=True)
            parser.make_qmetaobjecprivate()

def fix_thunk_func_name(ea, intendedName):
    if idc.get_func_attr(ea, FUNCATTR_FLAGS) & FUNC_THUNK == FUNC_THUNK:
        # thunk func, get real dest
        func = idaapi.get_func(ea)
        temp_ptr = idaapi.ea_pointer()
        target_ea = idaapi.calc_thunk_func_target(func, temp_ptr.cast())
        if target_ea != idaapi.BADADDR:
            idc.set_name(target_ea, intendedName, ida_name.SN_FORCE)
            idc.set_name(ea, "j_" + intendedName, ida_name.SN_FORCE)


# TODO: when superdata is not null
class QtMetaParser:
    def __init__(self, *args, **kwargs):
        is_dynamic = kwargs.get("is_dynamic")
        if is_dynamic: # dynamicMetaObject
            currFuncArr = kwargs.get("currFuncArr")
            print("begin currFuncArr")
            for tup in currFuncArr:
                print(','.join('{:02X}'.format(tup_member) for tup_member in tup))
            print("end currFuncArr")
            self.d = QMetaObject__d(currFuncArr[0][0], False)

            # fix QMetaObject__d location
            for idx, member in enumerate(self.d.c_struct):
                bytes_len = get_bytes_size(member[1])
                setattr(self.d, member[0], currFuncArr[idx][1])
                print(f"fixing {member[0]} to {hex(currFuncArr[idx][1])}")
            print(vars(self.d))
            self.d.make_struct(currFuncArr[0][0])
            
            self.str_data = self.get_str_data(self.d.stringdata)
            print(self.str_data)
            self.qmeta_obj_pri = QMetaObjectPrivate(self.d.data, self.str_data)
            class_name = self.str_data[self.qmeta_obj_pri.className].string
            class_spc = class_name + "::"
            idc.set_name(currFuncArr[0][0], class_name, SN_CHECK)
            idc.set_name(self.d.stringdata, class_spc + "stringdata", SN_CHECK)
            idc.set_name(self.d.data, class_spc + "data", SN_CHECK)
            if not idc.get_name(self.d.static_metacall, ida_name.GN_VISIBLE).startswith("nullsub"):
                idc.set_name(self.d.static_metacall, "", SN_CHECK)
                idc.set_name(self.d.static_metacall, class_spc + "static_metacall", SN_CHECK)
                fix_thunk_func_name(self.d.static_metacall, class_spc + "static_metacall")
        else:  # staticMetaObject
            d_offset = kwargs.get("d_offset")
            self.d_offset = d_offset
            self.d = QMetaObject__d(d_offset)
            self.d.make_struct(d_offset)
            self.str_data = self.get_str_data(self.d.stringdata)
            self.qmeta_obj_pri = QMetaObjectPrivate(self.d.data, self.str_data)
            class_name = self.str_data[self.qmeta_obj_pri.className].string
            class_spc = class_name + "::"
            idc.set_name(d_offset, class_name, SN_CHECK)
            idc.set_name(self.d.stringdata, class_spc + "stringdata", SN_CHECK)
            idc.set_name(self.d.data, class_spc + "data", SN_CHECK)
            if not idc.get_name(self.d.static_metacall, ida_name.GN_VISIBLE).startswith("nullsub"):
                idc.set_name(self.d.static_metacall, "", SN_CHECK)
                idc.set_name(self.d.static_metacall, class_spc + "static_metacall", SN_CHECK)
                fix_thunk_func_name(self.d.static_metacall, class_spc + "static_metacall")

    @staticmethod
    def get_str_data(str_off):
        start = str_off
        str_data = []
        while idc.get_wide_dword(start) == 0xFFFFFFFF and idc.get_wide_dword(start + 8) == 0:
            str_data.append(QArrayData(start))
            start += QArrayData.size
        return str_data

    def make_qmetaobjecprivate(self):
        # parse method
        start = self.qmeta_obj_pri.offset + (self.qmeta_obj_pri.methodData << 2)
        method_data = []
        for off in range(start, start + 4 * 5 * self.qmeta_obj_pri.methodCount, 4 * 5):
            qmthd = QMetaMethod(off, self.d.data, self.str_data)
            idc.set_cmt(qmthd.offset, "METHOD_%d " % len(method_data) + idc.get_cmt(qmthd.offset, 0), 0)
            method_data.append(qmthd)
        print(f"QMetaMethod {method_data}")


class Enum:
    def __init__(self, **entries): self.__dict__.update(entries)


class QMetaMethod:
    c_struct = [("name", FF_DATA | ida_bytes.FF_DWORD),
                ("parameterCount", FF_DATA | ida_bytes.FF_DWORD),
                ("typesDataIndex", FF_DATA | ida_bytes.FF_DWORD),
                ("tag", FF_DATA | ida_bytes.FF_DWORD),
                ("flag", FF_DATA | ida_bytes.FF_DWORD)]
    PropertyFlags = Enum(
        Invalid=0x00000000, Readable=0x00000001, Writable=0x00000002, Resettable=0x00000004,
        EnumOrFlag=0x00000008, StdCppSet=0x00000100, Override=0x00000200, Constant=0x00000400,
        Final=0x00000800, Designable=0x00001000, ResolveDesignable=0x00002000, Scriptable=0x00004000,
        ResolveScriptable=0x00008000, Stored=0x00010000, ResolveStored=0x00020000, Editable=0x00040000,
        ResolveEditable=0x00080000, User=0x00100000, ResolveUser=0x00200000, Notify=0x00400000,
        Revisioned=0x00800000
    )
    MethodFlags = Enum(
        AccessPrivate=0x00, AccessProtected=0x01, AccessPublic=0x02, AccessMask=0x03,
        MethodMethod=0x00, MethodSignal=0x04, MethodSlot=0x08, MethodConstructor=0x0c, MethodTypeMask=0x0c,
        MethodCompatibility=0x10, MethodCloned=0x20, MethodScriptable=0x40, MethodRevisioned=0x80
    )
    MethodTypesDict = {0x00: "METHOD", 0x04: "SIGNAL", 0x08: "SLOT", 0x0c: "CONSTRUCTOR"}
    MethodAccessDict = {0x00: "Private", 0x01: "Protected", 0x02: "Public"}

    QMetaType_map = {
        0: "UnknownType", 1: "Bool", 2: "Int", 3: "UInt", 4: "LongLong", 5: "ULongLong", 6: "Double",
        7: "QChar", 8: "QVariantMap", 9: "QVariantList", 10: "QString", 11: "QStringList",
        12: "QByteArray", 13: "QBitArray", 14: "QDate", 15: "QTime", 16: "QDateTime", 17: "QUrl",
        18: "QLocale", 19: "QRect", 20: "QRectF", 21: "QSize", 22: "QSizeF", 23: "QLine", 24: "QLineF",
        25: "QPoint", 26: "QPointF", 27: "QRegExp", 28: "QVariantHash", 29: "QEasingCurve", 30: "QUuid",
        31: "VoidStar", 32: "Long", 33: "Short", 34: "Char", 35: "ULong", 36: "UShort", 37: "UChar",
        38: "Float", 39: "QObjectStar", 40: "SChar", 41: "QVariant", 42: "QModelIndex", 43: "Void",
        44: "QRegularExpression", 45: "QJsonValue", 46: "QJsonObject", 47: "QJsonArray", 
        48: "QJsonDocument", 49: "QByteArrayList", 64: "QFont", 65: "QPixmap", 66: "QBrush", 
        67: "QColor", 68: "QPalette", 69: "QIcon", 70: "QImage", 71: "QPolygon", 72: "QRegion",
        73: "QBitmap", 74: "QCursor", 75: "QKeySequence", 76: "QPen", 77: "QTextLength",
        78: "QTextFormat", 79: "QMatrix", 80: "QTransform", 81: "QMatrix4x4", 82: "QVector2D",
        83: "QVector3D", 84: "QVector4D", 85: "QQuaternion", 86: "QPolygonF", 121: "QSizePolicy",
        1024: "User"
    }

    def get_type_str(self):
        method_type = self.flag & self.MethodFlags.MethodTypeMask
        cmmt = self.MethodTypesDict[method_type]
        access = self.flag & self.MethodFlags.AccessMask
        cmmt += " " + self.MethodAccessDict[access]
        if self.flag & self.MethodFlags.MethodCompatibility:
            cmmt += " Compatibility"
        elif self.flag & self.MethodFlags.MethodCloned:
            cmmt += " Cloned"
        elif self.flag & self.MethodFlags.MethodScriptable:
            cmmt += " Sciptable"
        elif self.flag & self.MethodFlags.MethodRevisioned:
            cmmt += " Revisioned"
        return cmmt

    def get_type(self, type_off, str_data_off):
        ida_bytes.del_items(type_off, 4, ida_bytes.DELIT_EXPAND)
        type_info = idc.get_wide_dword(type_off)
        if type_info in QMetaMethod.QMetaType_map:
            t = self.QMetaType_map[type_info]
        elif type_info & 0x80000000:
            type_info &= 0x7FFFFFFF
            t = str_data_off[type_info].string
        idc.set_cmt(type_off, t, 0)
        ida_bytes.create_data(type_off, ida_bytes.FF_DWORD, 4, ida_idaapi.BADADDR)
        return t

    def __init__(self, off, data_off, str_data_off):
        self.offset = off
        struct_map(self, self.c_struct, off)
        struct_maker(self, off)

        ret_type_off = data_off + self.typesDataIndex * 4
        ret_type_str = self.get_type(ret_type_off, str_data_off)
        paras_type_off = ret_type_off + 4
        para_type_strs = []
        for i in range(self.parameterCount):
            para_type_off = paras_type_off + i * 4
            para_type = self.get_type(para_type_off, str_data_off)
            para_type_strs.append(para_type)

        para_name_strs = []
        paras_name_off = paras_type_off + self.parameterCount * 4
        for i in range(self.parameterCount):
            para_name_off = paras_name_off + i * 4
            ida_bytes.del_items(para_name_off, 4, ida_bytes.DELIT_EXPAND)
            ida_bytes.create_data(para_name_off, ida_bytes.FF_DWORD, 4, ida_idaapi.BADADDR)
            para_name = str_data_off[idc.get_wide_dword(para_name_off)].string
            idc.set_cmt(para_name_off, para_name, 0)
            para_name_strs.append(para_name)

        paras_strs = map(lambda x, y: "%s %s" % (x, y), para_type_strs, para_name_strs)
        idc.set_cmt(off, "%s %s %s(%s)" % (self.get_type_str(), ret_type_str,
            str_data_off[self.name].string, ", ".join(paras_strs)), 0)


def get_bytes_size(data_flag):
    if ida_bytes.is_byte(data_flag):
        bytes_len = 1
    elif ida_bytes.is_word(data_flag):
        bytes_len = 2
    elif ida_bytes.is_dword(data_flag):
        bytes_len = 4
    elif ida_bytes.is_qword(data_flag):
        bytes_len = 8
    return bytes_len



def struct_map(obj, stru, off):
    for member in stru:
        bytes_len = get_bytes_size(member[1])
        setattr(obj, member[0], type_maker[bytes_len](off))
        off += bytes_len
    return off


class QMetaObject__d:
    """
struct QMetaObject::d { // private data
    const QMetaObject *superdata;
    const QByteArrayData *stringdata;  // QArrayData
    const uint *data;
    typedef void (*StaticMetacallFunction)(QObject *, QMetaObject::Call, int, void **);
    StaticMetacallFunction static_metacall;
    const QMetaObject * const *relatedMetaObjects;
    void *extradata; //reserved for future use
} d;
"""
    c_struct = [("superdata", ida_bytes.off_flag() | FF_DATA | ARCH_F),
                ("stringdata", ida_bytes.off_flag() | FF_DATA | ARCH_F),
                ("data", ida_bytes.off_flag() | FF_DATA | ARCH_F),
                ("static_metacall", ida_bytes.off_flag() | FF_DATA | ARCH_F),
                ("relatedMetaObjects", ida_bytes.off_flag() | FF_DATA | ARCH_F),
                ("extradata", ida_bytes.off_flag() | FF_DATA | ARCH_F)]

    def __init__(self, offset, no_map = False):
        if not no_map:  # no_map for dynamicMetaObject, we don't have real QMetaObject::d
            struct_map(self, self.c_struct, offset)


    def make_struct(self, offset):
        struct_maker(self, offset)


class QArrayData:
    """
struct QArrayData
{
    QtPrivate::RefCount ref;
    int size;
    uint alloc : 31;
    uint capacityReserved : 1;

    qptrdiff offset; // in bytes from beginning of header
};
static inline const QByteArray stringData(const QMetaObject *mo, int index)
{
    Q_ASSERT(priv(mo->d.data)->revision >= 7);
    const QByteArrayDataPtr data = { const_cast<QByteArrayData*>(&mo->d.stringdata[index]) };
    Q_ASSERT(data.ptr->ref.isStatic());
    Q_ASSERT(data.ptr->alloc == 0);
    Q_ASSERT(data.ptr->capacityReserved == 0);
    Q_ASSERT(data.ptr->size >= 0);
    return data;
}

"""
    if idc.__EA64__:
        size = 24
    else:
        size = 16

    c_struct = [("ref", FF_DATA | ida_bytes.FF_DWORD),
            ("size", FF_DATA | ARCH_F),
            ("alloc__capRved", FF_DATA | ida_bytes.FF_DWORD),
            ("offset", FF_DATA | ARCH_F) ]


    def __init__(self, beg_off):
        struct_map(self, self.c_struct, beg_off)
        struct_maker(self, beg_off)
        self.string = idc.get_strlit_contents(beg_off + self.offset, -1)
        if self.string is not None:
            self.string = self.string.decode('utf-8')
        else:
            self.string = ""

        alloc = 0x7FFFFFFF & self.alloc__capRved
        capacityReserved = self.alloc__capRved >> 31

        cmmt = "String: %s, alloc: %d, capRvrsd %d" % (self.string, capacityReserved, alloc)
        idc.set_cmt(beg_off, cmmt, 0)


    def __repr__(self):
        return "%s" % self.string


displayMetaDataForStaticMetaObj()
displayMetaDataForDynamicMetaObj()
