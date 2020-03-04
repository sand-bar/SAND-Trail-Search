'''
Created on Mar 1, 2019
@author: shawn chen
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import GenPerm as GenPerm
from ciphers import bat_lat

class Cipher(AbstractCipher):
    """
    Represents the linear behaviour of BAT and can be used
    to find differential characteristics for the given parameters.
    """

    name = "bat_linear_actsbox"
    rot_alpha = 0
    rot_beta = 4
    PERM = []

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x', 'y',
                'inS',
                'befP', 'aftP',
                'wiR',
                'sumw',
        ]

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for BAT nibble with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds   = parameters["rounds"]
        weight   = parameters["sweight"]
        if wordsize == 32:
            p = [7, 4, 1, 6, 3, 0, 5, 2]
        elif wordsize == 64:
            p = [14, 15, 8, 9, 2, 3, 12, 13, 6, 7, 0, 1, 10, 11, 4, 5]
        else:
            raise Exception("Wrong wordsize!")
        self.PERM = GenPerm.GenNibblePerms(wordsize, p)

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP: BAT linear actsbox\n"
                      "% w = {} alpha = {} beta = {}\n"
                      "% rounds = {}\n\n".format(
                        wordsize,
                        self.rot_alpha, self.rot_beta,
                        rounds))
            stp_file.write(header)

            # Setup variables
            # x = left, y = right
            x = ["x{}".format(i) for i in range(rounds + 1)]
            y = ["y{}".format(i) for i in range(rounds + 1)]
            in_S = ["inS{}".format(i) for i in range(rounds)]
            bef_P = ["befP{}".format(i) for i in range(rounds)]
            aft_P = ["aftP{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["sumw{}".format(i) for i in range(rounds)]
            w_i_0 = ["wiR{}".format(i) for i in range(rounds)]
            w_i_1 = ["wi1R{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, y, wordsize)
            stpcommands.setupVariables(stp_file, in_S, wordsize)
            stpcommands.setupVariables(stp_file, bef_P, wordsize)
            stpcommands.setupVariables(stp_file, aft_P, wordsize)
            stpcommands.setupVariables(stp_file, w, 16)
            stpcommands.setupVariables(stp_file, w_i_0, wordsize // 4)
            stpcommands.setupVariables(stp_file, w_i_1, wordsize // 4)

            stpcommands.setupWeightComputationSum(stp_file, weight, w, 16)

            self.SBOX_ACT_ASSERT(stp_file)

            for i in range(rounds):
                self.setupRound(stp_file,
                                     x[i], y[i],
                                     x[i+1], y[i+1],
                                     in_S[i],
                                     bef_P[i], aft_P[i],
                                     w[i], w_i_0[i], w_i_1[i], wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, [x[0], y[0]], wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, x[0], x[rounds])
                stpcommands.assertVariableValue(stp_file, y[0], y[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setupRound(self,
                        stp_file,
                        x_in, y_in,
                        x_out, y_out,
                        in_S,
                        bef_P, aft_P,
                        w, w_i_0, w_i_1, wordsize):
        """
        Model for behaviour of one round

        """
        command = ""

        # 1. left XOR branch: y_in = x_out = aft_P
        command += "ASSERT({} = {});\n".format(y_in, x_out)
        command += "ASSERT({} = {});\n".format(y_in, aft_P)

        # 2. left Copy branch: x_in ^ y_out = in_S
        command += "ASSERT({} = BVXOR({}, {}));\n".format(x_in, y_out, in_S)

        # 4. pass SSb (4-bit in, 8-bit out)
        in_0 = []
        out_0 = []
        out_1 = []
        w_i = []
        for i in range(wordsize // 4):
            s_out_4_bit_0 = "{0}[{1}:{1}]@{0}[{2}:{2}]@" \
                            "{0}[{3}:{3}]@{0}[{4}:{4}]".format(
                            bef_P,
                            wordsize - 1 - 4 * i - 0,
                            wordsize - 1 - 4 * i - 1,
                            wordsize - 1 - 4 * i - 2,
                            wordsize - 1 - 4 * i - 3)
            out_0.append(s_out_4_bit_0)
            out_1.append(s_out_4_bit_0)

            s_in_4_bit_S0 = "{0}[{1}:{1}]@{0}[{2}:{2}]@" \
                             "{0}[{3}:{3}]@{0}[{4}:{4}]".format(
                            in_S,
                            wordsize - 1 - 4 * i - 0,
                            wordsize - 1 - 4 * i - 1,
                            wordsize - 1 - 4 * i - 2,
                            wordsize - 1 - 4 * i - 3)
            in_0.append(s_in_4_bit_S0)

            s_w = "{0}[{1}:{1}]@{2}[{3}:{3}]".format(
                    w_i_1, wordsize // 4 - 1 - i,
                    w_i_0, wordsize // 4 - 1 - i)
            w_i.append(s_w)

        for i in range(wordsize // 4):
            s_in_out = "S[{}@{}@{}]".format(
            in_0[i],
            out_0[i],
            out_1[(i - (self.rot_beta - self.rot_alpha)//4) % (wordsize // 4)])
            command += "ASSERT({} = {});\n".format(w_i[i], s_in_out)
            command += "ASSERT(NOT({} = 0bin10));\n".format(w_i[i])

        # 5. perms
        for i in range(wordsize):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(
                    aft_P, self.PERM[i], bef_P, i)

        # 6. Weight computation
        sum_w_i = stpcommands.getWeightString([w_i_0], wordsize // 4, 0, w)
        sum_w_i += '\n'
        command += sum_w_i

        stp_file.write(command)
        return

    def SBOX_ACT_ASSERT(self, stp_file):
        command = "S: ARRAY BITVECTOR(12) OF BITVECTOR(2);\n"

        LDT = bat_lat.LAT
        for a in range(16):
            for b in range(256):
                t = abs(LDT[a][b])
                if t == 8:
                    command += "ASSERT(S[0bin{}{}] = 0bin00);\n".format(
                            "{:04b}".format(a),
                            "{:08b}".format(b),
                            )
                elif t != 0:
                    command += "ASSERT(S[0bin{}{}] = 0bin01);\n".format(
                            "{:04b}".format(a),
                            "{:08b}".format(b),
                            )
                else:
                    command += "ASSERT(S[0bin{}{}] = 0bin10);\n".format(
                            "{:04b}".format(a),
                            "{:08b}".format(b),
                            )
        stp_file.write(command)
        return
