//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: A template for headers.
// Copyright (c) 2013 EPAM Systems
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
#ifndef TEMPLATE_H
#define TEMPLATE_H
//------------------------------------------------------------------------------
#include <cstdint>  // include language headers in alphabetical order
#include <string>
//------------------------------------------------------------------------------
#define MY_MIN(a,b) (((a) < (b)) ? (a) : (b)) //!< This is example of preprocessor usage
//------------------------------------------------------------------------------
namespace hello
{

/*! \class Represents some entity
 */
class SayHello
{
public:
    SayHello();// May be uncommented
    ~SayHello();// May be uncommented

    SayHello(const SayHello&)            = delete;
    SayHello& operator=(const SayHello&) = delete;

    /*!  small functions may be implemented in-place
     * \return hello string
     */
    inline const std::string& say() const { return text; }

    /*! Sets some value
     * \param v - new value
     */
    void set_value(std::uint32_t v);

    /*! Returns value
     * \return value of sth
     */
    std::uint32_t get_value() const;

private:
    std::string text;//!< Hello phrase
    std::uint32_t value; //!< just a value for get/set methods

    static const unsigned int BAD_COFFEE;//!< Some constant
};

} // namespace hello
//------------------------------------------------------------------------------
#endif//TEMPLATE_H
//------------------------------------------------------------------------------
