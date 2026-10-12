/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
#ifndef INCLUDED_HANDLE_ANONGAME_PROTOS
#define INCLUDED_HANDLE_ANONGAME_PROTOS

#include "common/packet.h"
#include "common/bn_type.h"
#include "connection.h"

namespace pvpgn
{

	namespace bnetd
	{

		extern int handle_anongame_packet(t_connection * c, t_packet const * const packet);

		/* size a CLIENT_FINDANONGAME_INFOREQ must have to hold the noitems
		 * <tag><unknown> pairs (two bn_int each) that its header announces */
		static inline unsigned int anongame_inforeq_size(t_packet const * packet)
		{
			return sizeof(t_client_findanongame_inforeq) + bn_byte_get(packet->u.client_findanongame_inforeq.noitems) * 2 * sizeof(bn_int);
		}

	}

}

#endif
