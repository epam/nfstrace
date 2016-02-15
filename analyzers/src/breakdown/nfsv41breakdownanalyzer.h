//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: NFS v4.1 breakdown analyzer
// Copyright (c) 2015 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#ifndef NFSV41BREAKDOWNANALYZER_H
#define NFSV41BREAKDOWNANALYZER_H
//------------------------------------------------------------------------------
#include <api/plugin_api.h>

#include "nfsv4representer.h"
#include "statistics.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace breakdown
{
/*! \brief Analyzer for NFS v4.1
 * Handles NFS v4.1 commands
 */
class NFSv41BreakdownAnalyzer : virtual public IAnalyzer
{
    Statistics       compound_stats; //!< Statistics
    Statistics       stats;          //!< Statistics
    NFSv4Representer representer;    //!< Class for statistics representation
public:
    NFSv41BreakdownAnalyzer(std::ostream& o = std::cout);
    // NFSv4.1 procedures
    void compound41(const RPCProcedure* proc,
                    const struct NFS41::COMPOUND4args*,
                    const struct NFS41::COMPOUND4res*) override final;
    // NFSv4.1 operations
    void access41(const RPCProcedure* proc,
                  const struct NFS41::ACCESS4args*,
                  const struct NFS41::ACCESS4res* res) override final;

    void close41(const RPCProcedure* proc,
                 const struct NFS41::CLOSE4args*,
                 const struct NFS41::CLOSE4res* res) override final;
    void commit41(const RPCProcedure* proc,
                  const struct NFS41::COMMIT4args*,
                  const struct NFS41::COMMIT4res* res) override final;
    void create41(const RPCProcedure* proc,
                  const struct NFS41::CREATE4args*,
                  const struct NFS41::CREATE4res* res) override final;
    void delegpurge41(const RPCProcedure* proc,
                      const struct NFS41::DELEGPURGE4args*,
                      const struct NFS41::DELEGPURGE4res* res) override final;
    void delegreturn41(const RPCProcedure* proc,
                       const struct NFS41::DELEGRETURN4args*,
                       const struct NFS41::DELEGRETURN4res* res) override final;
    void getattr41(const RPCProcedure* proc,
                   const struct NFS41::GETATTR4args*,
                   const struct NFS41::GETATTR4res* res) override final;
    void getfh41(const RPCProcedure*            proc,
                 const struct NFS41::GETFH4res* res) override final;
    void link41(const RPCProcedure* proc,
                const struct NFS41::LINK4args*,
                const struct NFS41::LINK4res* res) override final;
    void lock41(const RPCProcedure* proc,
                const struct NFS41::LOCK4args*,
                const struct NFS41::LOCK4res* res) override final;
    void lockt41(const RPCProcedure* proc,
                 const struct NFS41::LOCKT4args*,
                 const struct NFS41::LOCKT4res* res) override final;
    void locku41(const RPCProcedure* proc,
                 const struct NFS41::LOCKU4args*,
                 const struct NFS41::LOCKU4res* res) override final;
    void lookup41(const RPCProcedure* proc,
                  const struct NFS41::LOOKUP4args*,
                  const struct NFS41::LOOKUP4res* res) override final;
    void lookupp41(const RPCProcedure*              proc,
                   const struct NFS41::LOOKUPP4res* res) override final;
    void nverify41(const RPCProcedure* proc,
                   const struct NFS41::NVERIFY4args*,
                   const struct NFS41::NVERIFY4res* res) override final;
    void open41(const RPCProcedure* proc,
                const struct NFS41::OPEN4args*,
                const struct NFS41::OPEN4res* res) override final;
    void openattr41(const RPCProcedure* proc,
                    const struct NFS41::OPENATTR4args*,
                    const struct NFS41::OPENATTR4res* res) override final;
    void open_confirm41(const RPCProcedure* proc,
                        const struct NFS41::OPEN_CONFIRM4args*,
                        const struct NFS41::OPEN_CONFIRM4res* res) override final;
    void open_downgrade41(const RPCProcedure* proc,
                          const struct NFS41::OPEN_DOWNGRADE4args*,
                          const struct NFS41::OPEN_DOWNGRADE4res* res) override final;
    void putfh41(const RPCProcedure* proc,
                 const struct NFS41::PUTFH4args*,
                 const struct NFS41::PUTFH4res* res) override final;
    void putpubfh41(const RPCProcedure*               proc,
                    const struct NFS41::PUTPUBFH4res* res) override final;
    void putrootfh41(const RPCProcedure*                proc,
                     const struct NFS41::PUTROOTFH4res* res) override final;
    void read41(const RPCProcedure* proc,
                const struct NFS41::READ4args*,
                const struct NFS41::READ4res* res) override final;
    void readdir41(const RPCProcedure* proc,
                   const struct NFS41::READDIR4args*,
                   const struct NFS41::READDIR4res* res) override final;
    void readlink41(const RPCProcedure*               proc,
                    const struct NFS41::READLINK4res* res) override final;
    void remove41(const RPCProcedure* proc,
                  const struct NFS41::REMOVE4args*,
                  const struct NFS41::REMOVE4res* res) override final;
    void rename41(const RPCProcedure* proc,
                  const struct NFS41::RENAME4args*,
                  const struct NFS41::RENAME4res* res) override final;
    void renew41(const RPCProcedure* proc,
                 const struct NFS41::RENEW4args*,
                 const struct NFS41::RENEW4res* res) override final;
    void restorefh41(const RPCProcedure*                proc,
                     const struct NFS41::RESTOREFH4res* res) override final;
    void savefh41(const RPCProcedure*             proc,
                  const struct NFS41::SAVEFH4res* res) override final;
    void secinfo41(const RPCProcedure* proc,
                   const struct NFS41::SECINFO4args*,
                   const struct NFS41::SECINFO4res* res) override final;
    void setattr41(const RPCProcedure* proc,
                   const struct NFS41::SETATTR4args*,
                   const struct NFS41::SETATTR4res* res) override final;
    void setclientid41(const RPCProcedure* proc,
                       const struct NFS41::SETCLIENTID4args*,
                       const struct NFS41::SETCLIENTID4res* res) override final;
    void setclientid_confirm41(const RPCProcedure* proc,
                               const struct NFS41::SETCLIENTID_CONFIRM4args*,
                               const struct NFS41::SETCLIENTID_CONFIRM4res* res) override final;
    void verify41(const RPCProcedure* proc,
                  const struct NFS41::VERIFY4args*,
                  const struct NFS41::VERIFY4res* res) override final;
    void write41(const RPCProcedure* proc,
                 const struct NFS41::WRITE4args*,
                 const struct NFS41::WRITE4res* res) override final;
    void release_lockowner41(const RPCProcedure* proc,
                             const struct NFS41::RELEASE_LOCKOWNER4args*,
                             const struct NFS41::RELEASE_LOCKOWNER4res* res) override final;
    void backchannel_ctl41(const RPCProcedure* proc,
                           const struct NFS41::BACKCHANNEL_CTL4args*,
                           const struct NFS41::BACKCHANNEL_CTL4res* res) override final;
    void bind_conn_to_session41(const RPCProcedure* proc,
                                const struct NFS41::BIND_CONN_TO_SESSION4args*,
                                const struct NFS41::BIND_CONN_TO_SESSION4res* res) override final;
    void exchange_id41(const RPCProcedure* proc,
                       const struct NFS41::EXCHANGE_ID4args*,
                       const struct NFS41::EXCHANGE_ID4res* res) override final;
    void create_session41(const RPCProcedure* proc,
                          const struct NFS41::CREATE_SESSION4args*,
                          const struct NFS41::CREATE_SESSION4res* res) override final;
    void destroy_session41(const RPCProcedure* proc,
                           const struct NFS41::DESTROY_SESSION4args*,
                           const struct NFS41::DESTROY_SESSION4res* res) override final;
    void free_stateid41(const RPCProcedure* proc,
                        const struct NFS41::FREE_STATEID4args*,
                        const struct NFS41::FREE_STATEID4res* res) override final;
    void get_dir_delegation41(const RPCProcedure* proc,
                              const struct NFS41::GET_DIR_DELEGATION4args*,
                              const struct NFS41::GET_DIR_DELEGATION4res* res) override final;
    void getdeviceinfo41(const RPCProcedure* proc,
                         const struct NFS41::GETDEVICEINFO4args*,
                         const struct NFS41::GETDEVICEINFO4res* res) override final;
    void getdevicelist41(const RPCProcedure* proc,
                         const struct NFS41::GETDEVICELIST4args*,
                         const struct NFS41::GETDEVICELIST4res* res) override final;
    void layoutcommit41(const RPCProcedure* proc,
                        const struct NFS41::LAYOUTCOMMIT4args*,
                        const struct NFS41::LAYOUTCOMMIT4res* res) override final;
    void layoutget41(const RPCProcedure* proc,
                     const struct NFS41::LAYOUTGET4args*,
                     const struct NFS41::LAYOUTGET4res* res) override final;
    void layoutreturn41(const RPCProcedure* proc,
                        const struct NFS41::LAYOUTRETURN4args*,
                        const struct NFS41::LAYOUTRETURN4res* res) override final;
    void secinfo_no_name41(const RPCProcedure* proc,
                           const NFS41::SECINFO_NO_NAME4args*,
                           const NFS41::SECINFO_NO_NAME4res* res) override final;
    void sequence41(const RPCProcedure* proc,
                    const struct NFS41::SEQUENCE4args*,
                    const struct NFS41::SEQUENCE4res* res) override final;
    void set_ssv41(const RPCProcedure* proc,
                   const struct NFS41::SET_SSV4args*,
                   const struct NFS41::SET_SSV4res* res) override final;
    void test_stateid41(const RPCProcedure* proc,
                        const struct NFS41::TEST_STATEID4args*,
                        const struct NFS41::TEST_STATEID4res* res) override final;
    void want_delegation41(const RPCProcedure* proc,
                           const struct NFS41::WANT_DELEGATION4args*,
                           const struct NFS41::WANT_DELEGATION4res* res) override final;
    void destroy_clientid41(const RPCProcedure* proc,
                            const struct NFS41::DESTROY_CLIENTID4args*,
                            const struct NFS41::DESTROY_CLIENTID4res* res) override final;
    void reclaim_complete41(const RPCProcedure* proc,
                            const struct NFS41::RECLAIM_COMPLETE4args*,
                            const struct NFS41::RECLAIM_COMPLETE4res* res) override final;
    void illegal41(const RPCProcedure*              proc,
                   const struct NFS41::ILLEGAL4res* res) override final;

    void flush_statistics() override;
};

} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif //NFSV41BREAKDOWNANALYZER_H
//------------------------------------------------------------------------------
