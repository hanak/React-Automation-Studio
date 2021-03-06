import React, { useRef, useEffect } from 'react';

import { makeStyles, useTheme } from '@material-ui/core/styles';
import TextInput from '../BaseComponents/TextInput';
import TextUpdateStatus from './TextUpdateStatus';
import TextUpdateStateful from './TextUpdateStateful';
import TextUpdateDate from './TextUpdateDate';
import TextUpdate from '../BaseComponents/TextUpdate';

import Table from '@material-ui/core/Table';
import TableBody from '@material-ui/core/TableBody';
import TableCell from '@material-ui/core/TableCell';
import TableContainer from '@material-ui/core/TableContainer';
import TableHead from '@material-ui/core/TableHead';
import TableRow from '@material-ui/core/TableRow';
import Paper from '@material-ui/core/Paper';

import Checkbox from '@material-ui/core/Checkbox';

import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';

import ListItemIcon from '@material-ui/core/ListItemIcon';
import Typography from '@material-ui/core/Typography';
import DoneAllIcon from '@material-ui/icons/DoneAll';

import Tooltip from '@material-ui/core/Tooltip';

// Styles
const useStyles = makeStyles(theme => ({
    root: {
        width: '100%',
        overflowY: 'auto',
    },
    TextFieldSeverityDisabled: {
        borderRadius: 2,
        padding: 1,
        backgroundColor: theme.palette.type === 'dark' ? theme.palette.grey[500] : theme.palette.grey[400]
    },
    styledTableHeadCell: {
        backgroundColor: theme.palette.type === 'dark' ? undefined : theme.palette.primary.light,
        color: theme.palette.type === 'dark' ? undefined : 'white',
    }

}));

const AlarmTable = props => {

    // console.log("AlarmTable rendered")

    const classes = useStyles()
    const theme = useTheme()
    const myRef = useRef()

    useEffect(() => {
        myRef.current.scrollTo(0, 0)
    }, [props.areaSelectedIndex])

    const { areaAlarms } = props;

    const isTopArea = !props.areaSelectedIndex.includes("=")
    let currSubArea = ""
    let newSubArea = false
    let currTopArea = ""
    let newTopArea = false

    const textFieldDisableClasses = {
        noAlarm: classes.TextFieldSeverityDisabled,
        minorAlarmAcked: classes.TextFieldSeverityDisabled,
        minorAlarm: classes.TextFieldSeverityDisabled,
        majorAlarmAcked: classes.TextFieldSeverityDisabled,
        majorAlarm: classes.TextFieldSeverityDisabled,
    }

    // console.log(props.alarmContextOpen)

    return (
        <TableContainer component={Paper} style={{ height: props.height }} ref={myRef} elevation={theme.palette.type === 'dark' ? undefined : 5}>
            <Table aria-label="Alarm Table" stickyHeader size="small">
                <TableHead>
                    <TableRow
                        onClick={(event) => {
                            event.preventDefault()
                            event.stopPropagation()
                        }}
                    >
                        {props.debug
                            ? <TableCell align="left" classes={{ stickyHeader: classes.styledTableHeadCell }}>TEST ALM</TableCell>
                            : null}
                        <TableCell align="left" classes={{ stickyHeader: classes.styledTableHeadCell }}>PV NAME</TableCell>
                        <TableCell align="center" classes={{ stickyHeader: classes.styledTableHeadCell }}>PV VALUE</TableCell>
                        <TableCell align="center" classes={{ stickyHeader: classes.styledTableHeadCell }}>ALM STATUS</TableCell>
                        <TableCell align="center" classes={{ stickyHeader: classes.styledTableHeadCell }}>LAST ALM VAL</TableCell>
                        <TableCell align="center" classes={{ stickyHeader: classes.styledTableHeadCell }}>LAST ALM TIME</TableCell>
                        <TableCell align="center" classes={{ stickyHeader: classes.styledTableHeadCell }}>LAST ALM ACK TIME</TableCell>
                        <TableCell align="center" classes={{ stickyHeader: classes.styledTableHeadCell }}>ENBL</TableCell>
                        <TableCell align="center" classes={{ stickyHeader: classes.styledTableHeadCell }}>LAT</TableCell>
                        <TableCell align="center" classes={{ stickyHeader: classes.styledTableHeadCell }}>NTFY</TableCell>
                    </TableRow>
                </TableHead>
                <TableBody>
                    {areaAlarms.map((entry, entryIndex) => {

                        const areaAlarmName = entry[0]
                        const value = entry[1]

                        const hostname = props.alarmPVDict[value["name"]].reduce((acc, entry, index) => {
                            if (index > 1) {
                                return `${acc}${entry}`
                            }
                            return acc
                        }, '')

                        const areaAlarmNameArray = areaAlarmName.split('=')
                        let areaName = null
                        let alarm = null
                        if (areaAlarmNameArray.length > 2) {
                            areaName = areaAlarmNameArray[0] + "=" + areaAlarmNameArray[1]
                            alarm = areaAlarmNameArray[2]
                            newTopArea = false
                            newSubArea = currSubArea !== areaName
                            currSubArea = areaName
                        }
                        else {
                            areaName = areaAlarmNameArray[0]
                            alarm = areaAlarmNameArray[1]
                            newSubArea = false
                            newTopArea = currTopArea !== areaName
                            currTopArea = areaName
                        }

                        const toolTipContents = props.alarmPVDict[value["name"]]
                            ? <p>
                                <b>Description: </b>{props.alarmPVDict[value["name"]][1]}<br />
                                <b>Host: </b>{hostname}<br />
                            </p>
                            : <p>
                                <b>Description: </b>{"Error connecting to pv"}<br />
                                <b>Host: </b>{"Error connecting to pv"}<br />
                            </p>

                        return (
                            <React.Fragment key={areaAlarmName}>
                                {newTopArea && props.alarmTableSearchString.length === 0
                                    ? <TableRow>
                                        <TableCell
                                            align="left"
                                            style={{
                                                paddingTop: 20,
                                                fontWeight: 'bold',
                                                borderBottom: 'outset'
                                            }}
                                        >
                                            {`${areaName.split('=')[0]}`}
                                        </TableCell>
                                        <TableCell style={{ borderBottom: 'outset' }}></TableCell>
                                        <TableCell style={{ borderBottom: 'outset' }}></TableCell>
                                        <TableCell style={{ borderBottom: 'outset' }}></TableCell>
                                        <TableCell style={{ borderBottom: 'outset' }}></TableCell>
                                        <TableCell style={{ borderBottom: 'outset' }}></TableCell>
                                        <TableCell style={{ borderBottom: 'outset' }}></TableCell>
                                        <TableCell style={{ borderBottom: 'outset' }}></TableCell>
                                        <TableCell style={{ borderBottom: 'outset' }}></TableCell>
                                        {props.debug
                                            ? <TableCell style={{ borderBottom: 'outset' }}></TableCell>
                                            : null}
                                    </TableRow>
                                    : null}
                                {isTopArea && newSubArea && props.alarmTableSearchString.length === 0
                                    ? <TableRow
                                        onClick={(event) => {
                                            event.preventDefault()
                                            event.stopPropagation()
                                        }}
                                    >
                                        <TableCell
                                            align="left"
                                            style={{
                                                paddingTop: 20,
                                                fontWeight: 'bold',
                                                borderBottom: 'outset'
                                            }}
                                        >
                                            {`${areaName.split('=')[0]} > ${areaName.split('=')[1]}`}
                                        </TableCell>
                                        <TableCell style={{ borderBottom: 'outset' }}></TableCell>
                                        <TableCell style={{ borderBottom: 'outset' }}></TableCell>
                                        <TableCell style={{ borderBottom: 'outset' }}></TableCell>
                                        <TableCell style={{ borderBottom: 'outset' }}></TableCell>
                                        <TableCell style={{ borderBottom: 'outset' }}></TableCell>
                                        <TableCell style={{ borderBottom: 'outset' }}></TableCell>
                                        <TableCell style={{ borderBottom: 'outset' }}></TableCell>
                                        <TableCell style={{ borderBottom: 'outset' }}></TableCell>
                                        {props.debug
                                            ? <TableCell style={{ borderBottom: 'outset' }}></TableCell>
                                            : null}
                                    </TableRow>
                                    : null}
                                <TableRow
                                    // key={areaAlarmName}
                                    hover={props.areaEnabled[areaName] && props.enableAllAreas}
                                    onContextMenu={event => props.tableItemRightClick(event, areaAlarmName, entryIndex)}
                                    selected={props.alarmRowSelected[areaAlarmName]}
                                    onClick={event => props.tableRowClick(event, `${areaName}*${value["name"]}`, areaAlarmName)}
                                >
                                    <Menu
                                        keepMounted
                                        open={props.alarmContextOpen[areaAlarmName] ? true : false}
                                        onClose={event => props.alarmContextClose(event, areaAlarmName)}
                                        anchorReference="anchorPosition"
                                        anchorPosition={props.contextMouseY !== null && props.contextMouseX !== null ?
                                            { top: props.contextMouseY, left: props.contextMouseX } : null}
                                    >
                                        <MenuItem
                                            onClick={event => props.alarmAcknowledge(event, areaAlarmName)}
                                        >
                                            <ListItemIcon >
                                                <DoneAllIcon fontSize="small" />
                                            </ListItemIcon>
                                            <Typography variant="inherit">Acknowledge Alarm</Typography>

                                        </MenuItem>

                                    </Menu>
                                    {props.debug
                                        ? <TableCell>
                                            <TextInput
                                                pv={'pva://' + value["name"]}
                                                usePvLabel={true}
                                                usePvPrecision={true}
                                                usePvUnits={true}
                                                usePvMinMax={true}
                                                alarmSensitive={true}
                                                disableContextMenu={true}
                                            />
                                        </TableCell>
                                        : null}
                                    <Tooltip
                                        title={
                                            <React.Fragment>
                                                <Typography color="inherit">{value["name"]}</Typography>
                                                {toolTipContents}
                                            </React.Fragment>
                                        }
                                        enterDelay={400}
                                    >
                                        <TableCell align="left">
                                            {value["name"]}
                                        </TableCell>
                                    </Tooltip>
                                    <TableCell align="center">
                                        <TextUpdateStateful
                                            pv={'pva://' + value["name"]}
                                            useStringValue={true}
                                            usePvUnits={true}
                                        />
                                    </TableCell>
                                    <TableCell align="center">
                                        <TextUpdateStatus
                                            pv={`pva://${props.alarmIOCPVPrefix}${value["name"]}A`}
                                            useStringValue={true}
                                            alarmSensitive={true}
                                            disableContextMenu={true}
                                            classes={
                                                props.enableAllAreas && props.areaEnabled[areaName] && value["enable"]
                                                    ? undefined
                                                    : textFieldDisableClasses
                                            }
                                            fadeTU={props.fadeTU}
                                        />
                                    </TableCell>

                                    <TableCell align="center">
                                        <TextUpdate
                                            pv={`pva://${props.alarmIOCPVPrefix}${value["name"]}V`}
                                            disableContextMenu={true}
                                        />
                                    </TableCell>
                                    <TableCell align="center">
                                        <TextUpdateDate
                                            pv={`pva://${props.alarmIOCPVPrefix}${value["name"]}T`}
                                            disableContextMenu={true}
                                            dateFormat="E, dd LLL yyyy 'at' HH:mm:ss"
                                        />
                                    </TableCell>
                                    <TableCell align="center">
                                        <TextUpdateDate
                                            pv={`pva://${props.alarmIOCPVPrefix}${value["name"]}K`}
                                            disableContextMenu={true}
                                            dateFormat="E, dd LLL yyyy 'at' HH:mm:ss"
                                        />
                                    </TableCell>
                                    <TableCell align="center">
                                        <Checkbox
                                            style={{ padding: 0, margin: 0 }}
                                            disabled={!props.areaEnabled[areaName] || !props.enableAllAreas}
                                            value={value["enable"]}
                                            color="primary"
                                            checked={value["enable"]}
                                            onClick={event => props.itemChecked(event, areaName, alarm, "enable", !value["enable"])}
                                        />
                                    </TableCell>
                                    <TableCell align="center">
                                        <Checkbox
                                            style={{ padding: 0, margin: 0 }}
                                            disabled={!props.areaEnabled[areaName] || !props.enableAllAreas}
                                            value={value["latch"]}
                                            color="primary"
                                            checked={value["latch"]}
                                            onClick={event => props.itemChecked(event, areaName, alarm, "latch", !value["latch"])}
                                        />
                                    </TableCell>
                                    <TableCell align="center">
                                        <Checkbox
                                            style={{ padding: 0, margin: 0 }}
                                            disabled={!props.areaEnabled[areaName] || !props.enableAllAreas}
                                            value={value["notify"]}
                                            color="primary"
                                            checked={value["notify"]}
                                            onClick={event => props.itemChecked(event, areaName, alarm, "notify", !value["notify"])}
                                        />
                                    </TableCell>
                                </TableRow>
                            </React.Fragment>
                        )

                    })}
                </TableBody>
            </Table>
        </TableContainer >
    )
}

export default React.memo(AlarmTable)