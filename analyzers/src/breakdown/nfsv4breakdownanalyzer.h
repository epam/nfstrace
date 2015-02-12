//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: NFS v4 breakdown analyzer
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
#ifndef NFSV4BREAKDOWNANALYZER_H
#define NFSV4BREAKDOWNANALYZER_H
//------------------------------------------------------------------------------
#include "nfsv3breakdownanalyzer.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace breakdown
{
/*! \brief Analyzer for NFS v4
 * Handles NFS v4 commands
 * Class is not inhereted or reimplement functions: it only extends it!
 */
class NFSv4BreakdownAnalyzer : public NFSv3BreakdownAnalyzer
{
protected:
    /**
     * @brief The NFSv4Representer class
     * Splits output into commands/operations lists
     */
    class NFSv4Representer : public Representer
    {
    public:
        NFSv4Representer(std::ostream& o, CommandRepresenter* cmdRep, size_t space_for_cmd_name);
        void onProcedureInfoPrinted(std::ostream& o, const BreakdownCounter& breakdown, unsigned procedure) const override final;
    };

    /**
     * @brief Composes 2 statistics: for procedures and functions
     */
    class StatisticsCompositor : public Statistics
    {
        Statistics& procedures_stats;
    public:
        StatisticsCompositor(Statistics& procedures_stats, Statistics& operations_stats);
        void for_each_procedure(std::function<void(const BreakdownCounter&, size_t)> on_procedure) const override;
        void for_each_procedure_in_session(const Session& session, std::function<void(const BreakdownCounter&, size_t)> on_procedure) const override;
    };

private:
    Statistics compound_stats;//!< Statistics
    Statistics stats;//!< Statistics
    NFSv4Representer representer;//!< stream to output
public:
    NFSv4BreakdownAnalyzer(std::ostream& o = std::cout);
    ~NFSv4BreakdownAnalyzer();

    // NFS4.0 procedures

    void null4(const RPCProcedure* proc,
               const struct NFS4::NULL4args*,
               const struct NFS4::NULL4res*) override final;
    void compound4(const RPCProcedure*  proc,
                   const struct NFS4::COMPOUND4args*,
                   const struct NFS4::COMPOUND4res*) override final;

    // NFS4.0 operations

    void access40(const RPCProcedure* proc,
                  const struct NFS4::ACCESS4args*,
                  const struct NFS4::ACCESS4res* res) override final;

    void close40(const RPCProcedure* proc,
                 const struct NFS4::CLOSE4args*,
                 const struct NFS4::CLOSE4res* res) override final;
    void commit40(const RPCProcedure* proc,
                  const struct NFS4::COMMIT4args*,
                  const struct NFS4::COMMIT4res* res) override final;
    void create40(const RPCProcedure* proc,
                  const struct NFS4::CREATE4args*,
                  const struct NFS4::CREATE4res* res) override final;
    void delegpurge40(const RPCProcedure* proc,
                      const struct NFS4::DELEGPURGE4args*,
                      const struct NFS4::DELEGPURGE4res* res) override final;
    void delegreturn40(const RPCProcedure* proc,
                       const struct NFS4::DELEGRETURN4args*,
                       const struct NFS4::DELEGRETURN4res* res) override final;
    void getattr40(const RPCProcedure* proc,
                   const struct NFS4::GETATTR4args*,
                   const struct NFS4::GETATTR4res* res) override final;
    void getfh40(const RPCProcedure* proc,
                 const struct NFS4::GETFH4res* res) override final;
    void link40(const RPCProcedure* proc,
                const struct NFS4::LINK4args*,
                const struct NFS4::LINK4res* res) override final;
    void lock40(const RPCProcedure* proc,
                const struct NFS4::LOCK4args*,
                const struct NFS4::LOCK4res* res) override final;
    void lockt40(const RPCProcedure* proc,
                 const struct NFS4::LOCKT4args*,
                 const struct NFS4::LOCKT4res* res) override final;
    void locku40(const RPCProcedure* proc,
                 const struct NFS4::LOCKU4args*,
                 const struct NFS4::LOCKU4res* res) override final;
    void lookup40(const RPCProcedure* proc,
                  const struct NFS4::LOOKUP4args*,
                  const struct NFS4::LOOKUP4res* res) override final;
    void lookupp40(const RPCProcedure* proc,
                   const struct NFS4::LOOKUPP4res* res) override final;
    void nverify40(const RPCProcedure* proc,
                   const struct NFS4::NVERIFY4args*,
                   const struct NFS4::NVERIFY4res* res) override final;
    void open40(const RPCProcedure* proc,
                const struct NFS4::OPEN4args*,
                const struct NFS4::OPEN4res* res) override final;
    void openattr40(const RPCProcedure* proc,
                    const struct NFS4::OPENATTR4args*,
                    const struct NFS4::OPENATTR4res* res) override final;
    void open_confirm40(const RPCProcedure* proc,
                        const struct NFS4::OPEN_CONFIRM4args*,
                        const struct NFS4::OPEN_CONFIRM4res* res) override final;
    void open_downgrade40(const RPCProcedure* proc,
                          const struct NFS4::OPEN_DOWNGRADE4args*,
                          const struct NFS4::OPEN_DOWNGRADE4res* res) override final;
    void putfh40(const RPCProcedure* proc,
                 const struct NFS4::PUTFH4args*,
                 const struct NFS4::PUTFH4res* res) override final;
    void putpubfh40(const RPCProcedure* proc,
                    const struct NFS4::PUTPUBFH4res* res) override final;
    void putrootfh40(const RPCProcedure* proc,
                     const struct NFS4::PUTROOTFH4res* res) override final;
    void read40(const RPCProcedure* proc,
                const struct NFS4::READ4args*,
                const struct NFS4::READ4res* res) override final;
    void readdir40(const RPCProcedure* proc,
                   const struct NFS4::READDIR4args*,
                   const struct NFS4::READDIR4res* res) override final;
    void readlink40(const RPCProcedure* proc,
                    const struct NFS4::READLINK4res* res) override final;
    void remove40(const RPCProcedure* proc,
                  const struct NFS4::REMOVE4args*,
                  const struct NFS4::REMOVE4res* res) override final;
    void rename40(const RPCProcedure* proc,
                  const struct NFS4::RENAME4args*,
                  const struct NFS4::RENAME4res* res) override final;
    void renew40(const RPCProcedure* proc,
                 const struct NFS4::RENEW4args*,
                 const struct NFS4::RENEW4res* res) override final;
    void restorefh40(const RPCProcedure* proc,
                     const struct NFS4::RESTOREFH4res* res) override final;
    void savefh40(const RPCProcedure* proc,
                  const struct NFS4::SAVEFH4res* res) override final;
    void secinfo40(const RPCProcedure* proc,
                   const struct NFS4::SECINFO4args*,
                   const struct NFS4::SECINFO4res* res) override final;
    void setattr40(const RPCProcedure* proc,
                   const struct NFS4::SETATTR4args*,
                   const struct NFS4::SETATTR4res* res) override final;
    void setclientid40(const RPCProcedure* proc,
                       const struct NFS4::SETCLIENTID4args*,
                       const struct NFS4::SETCLIENTID4res* res) override final;
    void setclientid_confirm40(const RPCProcedure* proc,
                               const struct NFS4::SETCLIENTID_CONFIRM4args*,
                               const struct NFS4::SETCLIENTID_CONFIRM4res* res) override final;
    void verify40(const RPCProcedure* proc,
                  const struct NFS4::VERIFY4args*,
                  const struct NFS4::VERIFY4res* res) override final;
    void write40(const RPCProcedure* proc,
                 const struct NFS4::WRITE4args*,
                 const struct NFS4::WRITE4res* res) override final;
    void release_lockowner40(const RPCProcedure* proc,
                             const struct NFS4::RELEASE_LOCKOWNER4args*,
                             const struct NFS4::RELEASE_LOCKOWNER4res* res) override final;
    void get_dir_delegation40(const RPCProcedure* proc,
                              const struct NFS4::GET_DIR_DELEGATION4args*,
                              const struct NFS4::GET_DIR_DELEGATION4res* res) override final;
    void illegal40(const RPCProcedure* proc,
                   const struct NFS4::ILLEGAL4res* res) override final;
    void flush_statistics() override;
};

} // protocols
} // NST
//------------------------------------------------------------------------------
#endif // NFSV4BREAKDOWNANALYZER_H
//------------------------------------------------------------------------------

