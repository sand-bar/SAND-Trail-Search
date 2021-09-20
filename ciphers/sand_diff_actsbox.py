'''
Created on Mar 1, 2019
@author: Shawn
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher
from ciphers import GenPerm as GenPerm
from ciphers import ssb_ddt

from parser.stpcommands import getStringLeftRotate as rotl

class Cipher(AbstractCipher):
    """
    Represents the differential behaviour of sand and can be used
    to find differential characteristics for the given parameters.
    """

    name = "sand_diff_actsbox"
    rot_alpha = 0
    rot_beta = 4
    PERM = []

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['x', 'y',
                "outG0", "outG1",
                "rotG0", "rotG1",
                "xorG", "permG",
                "sumw",
                ]

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for sand diff pattern with
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
            header = ("% Input File for STP: sand diff actsbox\n"
                      "% w = {} alpha = {} beta = {}\n"
                      "% rounds = {}\n\n".format(
                        wordsize,
                        self.rot_alpha, self.rot_beta,
                        rounds))
            stp_file.write(header)

            # Setup variables
            # x as left, y as right
            x = ["x{}".format(i) for i in range(rounds + 1)]
            y = ["y{}".format(i) for i in range(rounds + 1)]
            out_G0  = ["outG0{}".format(i) for i in range(rounds)]
            out_G1  = ["outG1{}".format(i) for i in range(rounds)]
            rot_G0  = ["rotG0{}".format(i) for i in range(rounds)]
            rot_G1  = ["rotG1{}".format(i) for i in range(rounds)]
            xor_G  = ["xorG{}".format(i) for i in range(rounds)]
            perm_G  = ["permG{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["sumw{}".format(i) for i in range(rounds)]
            act_flag = ["actflag{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, x, wordsize)
            stpcommands.setupVariables(stp_file, y, wordsize)
            stpcommands.setupVariables(stp_file, out_G0, wordsize)
            stpcommands.setupVariables(stp_file, out_G1, wordsize)
            stpcommands.setupVariables(stp_file, rot_G0, wordsize)
            stpcommands.setupVariables(stp_file, rot_G1, wordsize)
            stpcommands.setupVariables(stp_file, xor_G, wordsize)
            stpcommands.setupVariables(stp_file, perm_G, wordsize)
            stpcommands.setupVariables(stp_file, w, 16)
            stpcommands.setupVariables(stp_file, act_flag, wordsize // 4)

            stpcommands.setupWeightComputationSum(stp_file, weight, w, 16)

            self.SBOX_ACT_ASSERT(stp_file)

            for i in range(rounds):
                self.setupRound(stp_file,
                                     x[i], y[i],
                                     x[i+1], y[i+1],
                                     out_G0[i], out_G1[i],
                                     rot_G0[i], rot_G1[i],
                                     xor_G[i], perm_G[i],
                                     act_flag[i], w[i], wordsize)

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
                        out_G0, out_G1,
                        rot_G0, rot_G1,
                        xor_G, perm_G,
                        act_flag, w, wordsize):
        """
        Model for differential behaviour of one round
        """
        command = ""

        # 1. y_out = x_in
        command += "ASSERT({} = {});\n".format(y_out, x_in)

        # 2. pass SSb: x -> out_G0, out_G1
        for i in range(wordsize // 4):
            s_in_4_bit = "{0}[{1}:{1}]@{0}[{2}:{2}]@" \
                         "{0}[{3}:{3}]@{0}[{4}:{4}]".format(
                            x_in,
                            wordsize - 1 - 4 * i - 0,
                            wordsize - 1 - 4 * i - 1,
                            wordsize - 1 - 4 * i - 2,
                            wordsize - 1 - 4 * i - 3,
                            )
            s_out_4_bit_G0 = "{0}[{1}:{1}]@{0}[{2}:{2}]@" \
                             "{0}[{3}:{3}]@{0}[{4}:{4}]".format(
                            out_G0,
                            wordsize - 1 - 4 * i - 0,
                            wordsize - 1 - 4 * i - 1,
                            wordsize - 1 - 4 * i - 2,
                            wordsize - 1 - 4 * i - 3,
                            )
            s_out_4_bit_G1 = "{0}[{1}:{1}]@{0}[{2}:{2}]@" \
                             "{0}[{3}:{3}]@{0}[{4}:{4}]".format(
                            out_G1,
                            wordsize - 1 - 4 * i - 0,
                            wordsize - 1 - 4 * i - 1,
                            wordsize - 1 - 4 * i - 2,
                            wordsize - 1 - 4 * i - 3,
                            )
            command += "ASSERT(SBOX[{}@{}@{}] = 0bin1);\n".format(
                        s_in_4_bit, s_out_4_bit_G0, s_out_4_bit_G1)
            command += "ASSERT({1} = (IF {0} = 0bin0000 " \
                                            "THEN 0bin0 " \
                                      "ELSE 0bin1 ENDIF));\n".format(
                        s_in_4_bit,
                        "{0}[{1}:{1}]".format(act_flag, wordsize // 4 - 1 - i))

        # 3. rot out_G0, out_G1
        out_G0_rotalpha = rotl(out_G0, self.rot_alpha, wordsize)
        out_G1_rotbeta  = rotl(out_G1, self.rot_beta,  wordsize)
        command += "ASSERT({} = {});\n".format(rot_G0, out_G0_rotalpha)
        command += "ASSERT({} = {});\n".format(rot_G1, out_G1_rotbeta)

        # 4. G0 ^ G1 = xor_G
        command += "ASSERT({} = BVXOR({}, {}));\n".format(xor_G, rot_G0, rot_G1)

        # 4. xor_G PERM to perm_G
        for i in range(wordsize):
            command += "ASSERT({0}[{1}:{1}] = {2}[{3}:{3}]);\n".format(
                    perm_G, self.PERM[i], xor_G, i)

        # 5. perm_G ^ y_in = x_out
        command += "ASSERT({} = BVXOR({}, {}));\n".format(y_in, perm_G, x_out)

        # 6. Weight computation
        sum_w_i = stpcommands.getWeightString([act_flag], wordsize // 4, 0, w)
        sum_w_i += '\n'
        command += sum_w_i

        stp_file.write(command)
        return

    def SBOX_ACT_ASSERT(self, stp_file):
        command = "SBOX : ARRAY BITVECTOR(12) OF BITVECTOR(1);\n"

        DDT = ssb_ddt.DDT
        for i in range(16):
            for j in range(256):
                if DDT[i][j] != 0:
                    command += "ASSERT(SBOX[0bin{}{}] = 0bin1);\n".format(
                            "{:04b}".format(i),
                            "{:08b}".format(j))
                else:
                    command += "ASSERT(SBOX[0bin{}{}] = 0bin0);\n".format(
                            "{:04b}".format(i),
                            "{:08b}".format(j))

        stp_file.write(command)
        return
