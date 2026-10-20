import {
  BridgeIn as BridgeInEvent,
  BridgeInRequest as BridgeInRequestEvent,
  CancelWithdraw as CancelWithdrawEvent,
  CommitteeResponse as CommitteeResponseEvent,
  InitWithdraw as InitWithdrawEvent,
  Initialized as InitializedEvent,
  PostGraphData as PostGraphDataEvent,
  ProceedWithdraw as ProceedWithdrawEvent,
  WithdrawDisproved as WithdrawDisprovedEvent,
  WithdrawHappyPath as WithdrawHappyPathEvent,
  WithdrawUnhappyPath as WithdrawUnhappyPathEvent
} from "../generated/GatewayUpgradeable/GatewayUpgradeable"
import {
  BridgeIn,
  BridgeInRequest,
  CancelWithdraw,
  CommitteeResponse,
  InitWithdraw,
  Initialized,
  PostGraphData,
  ProceedWithdraw,
  WithdrawDisproved,
  WithdrawHappyPath,
  WithdrawUnhappyPath
} from "../generated/schema"
import { Bytes } from "@graphprotocol/graph-ts"

export function handleBridgeIn(event: BridgeInEvent): void {
  let entity = new BridgeIn(
    event.transaction.hash.concatI32(event.logIndex.toI32())
  )
  entity.depositorAddress = event.params.depositorAddress
  entity.instanceId = event.params.instanceId
  entity.peginAmountSats = event.params.peginAmountSats
  entity.feeAmountSats = event.params.feeAmountSats

  entity.blockNumber = event.block.number
  entity.blockTimestamp = event.block.timestamp
  entity.transactionHash = event.transaction.hash

  entity.save()
}

export function handleBridgeInRequest(event: BridgeInRequestEvent): void {
  let entity = new BridgeInRequest(
    event.transaction.hash.concatI32(event.logIndex.toI32())
  )
  entity.instanceId = event.params.instanceId
  entity.depositorAddress = event.params.depositorAddress
  entity.peginAmountSats = event.params.peginAmountSats
  entity.txnFees = event.params.txnFees
  entity.userInputs = changetype<Bytes[]>(event.params.userInputs)
  entity.userXonlyPubkey = event.params.userXonlyPubkey
  entity.userChangeAddress = event.params.userChangeAddress
  entity.userRefundAddress = event.params.userRefundAddress

  entity.blockNumber = event.block.number
  entity.blockTimestamp = event.block.timestamp
  entity.transactionHash = event.transaction.hash

  entity.save()
}

export function handleCancelWithdraw(event: CancelWithdrawEvent): void {
  let entity = new CancelWithdraw(
    event.transaction.hash.concatI32(event.logIndex.toI32())
  )
  entity.instanceId = event.params.instanceId
  entity.graphId = event.params.graphId
  entity.triggerAddress = event.params.triggerAddress

  entity.blockNumber = event.block.number
  entity.blockTimestamp = event.block.timestamp
  entity.transactionHash = event.transaction.hash

  entity.save()
}

export function handleCommitteeResponse(event: CommitteeResponseEvent): void {
  let entity = new CommitteeResponse(
    event.transaction.hash.concatI32(event.logIndex.toI32())
  )
  entity.instanceId = event.params.instanceId
  entity.committeeAddress = event.params.committeeAddress
  entity.committeePubkey = event.params.committeePubkey

  entity.blockNumber = event.block.number
  entity.blockTimestamp = event.block.timestamp
  entity.transactionHash = event.transaction.hash

  entity.save()
}

export function handleInitWithdraw(event: InitWithdrawEvent): void {
  let entity = new InitWithdraw(
    event.transaction.hash.concatI32(event.logIndex.toI32())
  )
  entity.instanceId = event.params.instanceId
  entity.graphId = event.params.graphId
  entity.operatorAddress = event.params.operatorAddress
  entity.withdrawAmountSats = event.params.withdrawAmountSats

  entity.blockNumber = event.block.number
  entity.blockTimestamp = event.block.timestamp
  entity.transactionHash = event.transaction.hash

  entity.save()
}

export function handleInitialized(event: InitializedEvent): void {
  let entity = new Initialized(
    event.transaction.hash.concatI32(event.logIndex.toI32())
  )
  entity.version = event.params.version

  entity.blockNumber = event.block.number
  entity.blockTimestamp = event.block.timestamp
  entity.transactionHash = event.transaction.hash

  entity.save()
}

export function handlePostGraphData(event: PostGraphDataEvent): void {
  let entity = new PostGraphData(
    event.transaction.hash.concatI32(event.logIndex.toI32())
  )
  entity.instanceId = event.params.instanceId
  entity.graphId = event.params.graphId

  entity.blockNumber = event.block.number
  entity.blockTimestamp = event.block.timestamp
  entity.transactionHash = event.transaction.hash

  entity.save()
}

export function handleProceedWithdraw(event: ProceedWithdrawEvent): void {
  let entity = new ProceedWithdraw(
    event.transaction.hash.concatI32(event.logIndex.toI32())
  )
  entity.instanceId = event.params.instanceId
  entity.graphId = event.params.graphId
  entity.kickoffTxid = event.params.kickoffTxid

  entity.blockNumber = event.block.number
  entity.blockTimestamp = event.block.timestamp
  entity.transactionHash = event.transaction.hash

  entity.save()
}

export function handleWithdrawDisproved(event: WithdrawDisprovedEvent): void {
  let entity = new WithdrawDisproved(
    event.transaction.hash.concatI32(event.logIndex.toI32())
  )
  entity.instanceId = event.params.instanceId
  entity.graphId = event.params.graphId
  entity.disproveTxType = event.params.disproveTxType
  entity.txnIndex = event.params.txnIndex
  entity.challengeStartTxid = event.params.challengeStartTxid
  entity.challengeFinishTxid = event.params.challengeFinishTxid
  entity.challengerAddress = event.params.challengerAddress
  entity.disproverAddress = event.params.disproverAddress
  entity.challengerRewardAmount = event.params.challengerRewardAmount
  entity.disproverRewardAmount = event.params.disproverRewardAmount

  entity.blockNumber = event.block.number
  entity.blockTimestamp = event.block.timestamp
  entity.transactionHash = event.transaction.hash

  entity.save()
}

export function handleWithdrawHappyPath(event: WithdrawHappyPathEvent): void {
  let entity = new WithdrawHappyPath(
    event.transaction.hash.concatI32(event.logIndex.toI32())
  )
  entity.instanceId = event.params.instanceId
  entity.graphId = event.params.graphId
  entity.take1Txid = event.params.take1Txid
  entity.operatorAddress = event.params.operatorAddress
  entity.rewardAmountSats = event.params.rewardAmountSats

  entity.blockNumber = event.block.number
  entity.blockTimestamp = event.block.timestamp
  entity.transactionHash = event.transaction.hash

  entity.save()
}

export function handleWithdrawUnhappyPath(
  event: WithdrawUnhappyPathEvent
): void {
  let entity = new WithdrawUnhappyPath(
    event.transaction.hash.concatI32(event.logIndex.toI32())
  )
  entity.instanceId = event.params.instanceId
  entity.graphId = event.params.graphId
  entity.take2Txid = event.params.take2Txid
  entity.operatorAddress = event.params.operatorAddress
  entity.rewardAmountSats = event.params.rewardAmountSats

  entity.blockNumber = event.block.number
  entity.blockTimestamp = event.block.timestamp
  entity.transactionHash = event.transaction.hash

  entity.save()
}
